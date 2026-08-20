package auth

import (
	"context"
	"errors"
	"log"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Principal struct {
	Subject, TenantID, Environment, ApplicationID, AuthorizedParty string
	Scopes                                                         map[string]struct{}
}

func (p Principal) HasScope(v string) bool { _, ok := p.Scopes[v]; return ok }

type Verifier interface {
	Verify(context.Context, string) (Principal, error)
}

type OIDCVerifier struct {
	verifier    *oidc.IDTokenVerifier
	environment string
	issuer      string
	audience    string
}

func New(ctx context.Context, issuer, audience, environment string) (*OIDCVerifier, error) {
	p, e := oidc.NewProvider(ctx, issuer)
	if e != nil {
		return nil, e
	}
	return &OIDCVerifier{
		verifier:    p.Verifier(&oidc.Config{ClientID: audience}),
		environment: environment,
		issuer:      issuer,
		audience:    audience,
	}, nil
}

func (v *OIDCVerifier) Verify(ctx context.Context, raw string) (Principal, error) {
	token, e := v.verifier.Verify(ctx, raw)
	if e != nil {
		log.Printf("[OIDC-DEBUG] Verify failed: issuer=%s audience=%s error=%v", v.issuer, v.audience, e)
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
	if c.Subject == "" {
		return Principal{}, errors.New("required token context missing")
	}
	if c.TenantID == "" && c.AuthorizedParty == "" {
		return Principal{}, errors.New("required token context missing")
	}
	s := map[string]struct{}{}
	for _, x := range strings.Fields(c.Scope) {
		s[x] = struct{}{}
	}
	log.Printf("[OIDC-DEBUG] Verified OK: sub=%s azp=%s tenant=%s env=%s scope=%s", c.Subject, c.AuthorizedParty, c.TenantID, c.Environment, c.Scope)
	return Principal{c.Subject, c.TenantID, c.Environment, c.ApplicationID, c.AuthorizedParty, s}, nil
}

