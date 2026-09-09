package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Principal struct {
	Subject, TenantID, Environment, ApplicationID, AuthorizedParty string
	Scopes                                                         map[string]struct{}
	TrustedInternal                                                bool
}

func (p Principal) HasScope(v string) bool { _, ok := p.Scopes[v]; return ok }

type Verifier interface {
	Verify(context.Context, string) (Principal, error)
}

type OIDCVerifier struct {
	verifier        *oidc.IDTokenVerifier
	environment     string
	issuer          string
	audience        string
	trustedInternal map[string]bool
}

func New(ctx context.Context, issuer, audience, environment string, trustedClients ...string) (*OIDCVerifier, error) {
	trusted := map[string]bool{}
	for _, client := range trustedClients {
		client = strings.TrimSpace(client)
		if client == "" {
			continue
		}
		if strings.ContainsAny(client, "* \t\r\n") || strings.HasPrefix(client, "efc_") {
			return nil, errors.New("trusted internal clients must be explicit service client IDs")
		}
		trusted[client] = true
	}
	p, e := oidc.NewProvider(ctx, issuer)
	if e != nil {
		return nil, e
	}
	return &OIDCVerifier{
		verifier:        p.Verifier(&oidc.Config{ClientID: audience}),
		environment:     environment,
		issuer:          issuer,
		audience:        audience,
		trustedInternal: trusted,
	}, nil
}

func (v *OIDCVerifier) Verify(ctx context.Context, raw string) (Principal, error) {
	token, e := v.verifier.Verify(ctx, raw)
	if e != nil {
		return Principal{}, e
	}
	var c struct {
		Subject         string `json:"sub"`
		TenantID        string `json:"tenant_id"`
		Environment     string `json:"environment"`
		ApplicationID   string `json:"application_id"`
		AuthorizedParty string `json:"azp"`
		Scope           string `json:"scope"`
	}
	if e = token.Claims(&c); e != nil {
		return Principal{}, e
	}
	if e = validateContext(c.Subject, c.TenantID, c.Environment, c.AuthorizedParty, v.environment); e != nil {
		return Principal{}, e
	}
	s := map[string]struct{}{}
	for _, x := range strings.Fields(c.Scope) {
		s[x] = struct{}{}
	}
	if c.Environment == "" {
		c.Environment = v.environment
	}
	return Principal{Subject: c.Subject, TenantID: c.TenantID, Environment: c.Environment, ApplicationID: c.ApplicationID, AuthorizedParty: c.AuthorizedParty, Scopes: s, TrustedInternal: trustedInternal(c.TenantID, c.ApplicationID, c.AuthorizedParty, v.trustedInternal)}, nil
}

func trustedInternal(tenant, application, client string, allowlist map[string]bool) bool {
	return tenant == "" && application == "" && client != "" && allowlist[client]
}

func validateContext(subject, tenant, environment, client, deployment string) error {
	if subject == "" || (tenant == "" && client == "") {
		return errors.New("required token context missing")
	}
	// Legacy internal service credentials may omit tenant/environment; their
	// document scope is resolved by the service. Tenant credentials may not.
	if (tenant != "" && environment == "") || (environment != "" && environment != deployment) {
		return errors.New("token environment does not match this deployment")
	}
	return nil
}
