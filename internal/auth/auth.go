package auth

import (
	"context"
	"errors"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
)

type Principal struct {
	Subject, TenantID, Environment, ApplicationID string
	Scopes                                        map[string]struct{}
}

func (p Principal) HasScope(v string) bool { _, ok := p.Scopes[v]; return ok }

type Verifier interface {
	Verify(context.Context, string) (Principal, error)
}
type OIDCVerifier struct {
	verifier    *oidc.IDTokenVerifier
	environment string
}

func New(ctx context.Context, issuer, audience, environment string) (*OIDCVerifier, error) {
	p, e := oidc.NewProvider(ctx, issuer)
	if e != nil {
		return nil, e
	}
	return &OIDCVerifier{p.Verifier(&oidc.Config{ClientID: audience}), environment}, nil
}
func (v *OIDCVerifier) Verify(ctx context.Context, raw string) (Principal, error) {
	token, e := v.verifier.Verify(ctx, raw)
	if e != nil {
		return Principal{}, e
	}
	var c struct {
		Subject       string `json:"sub"`
		TenantID      string `json:"tenant_id"`
		Environment   string `json:"environment"`
		ApplicationID string `json:"application_id"`
		Scope         string `json:"scope"`
	}
	if e = token.Claims(&c); e != nil {
		return Principal{}, e
	}
	if c.Subject == "" || c.TenantID == "" || c.Environment != v.environment {
		return Principal{}, errors.New("required token context missing")
	}
	s := map[string]struct{}{}
	for _, x := range strings.Fields(c.Scope) {
		s[x] = struct{}{}
	}
	return Principal{c.Subject, c.TenantID, c.Environment, c.ApplicationID, s}, nil
}
