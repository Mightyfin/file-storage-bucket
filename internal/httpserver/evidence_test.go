package httpserver

import (
	"context"
	"github.com/Mightyfin/file-storage-bucket/internal/auth"
	"github.com/Mightyfin/file-storage-bucket/internal/documents"
	"net/http/httptest"
	"strings"
	"testing"
)

type evidenceFake struct {
	calls int
	scope documents.Scope
}

func (f *evidenceFake) Evidence(_ context.Context, s documents.Scope, id, party, digest string) (documents.Document, error) {
	f.calls++
	f.scope = s
	return documents.Document{ID: id, PartyID: party}, nil
}
func TestEvidenceRequiresTrustedScope(t *testing.T) {
	for _, tc := range []struct {
		name, tenant, env, permission, body string
		want                                int
	}{
		{"valid", "tenant-a", "sandbox", "documents.evidence.verify", `{"party_id":"party-a","sha256":"digest"}`, 200},
		{"machine_without_tenant", "", "sandbox", "documents.evidence.verify", `{}`, 403},
		{"missing_environment", "tenant-a", "", "documents.evidence.verify", `{}`, 403},
		{"foreign_environment", "tenant-a", "production", "documents.evidence.verify", `{}`, 403},
		{"read_is_not_verify", "tenant-a", "sandbox", "documents.read", `{}`, 403},
		{"body_scope_override", "tenant-a", "sandbox", "documents.evidence.verify", `{"tenant_id":"tenant-b"}`, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &evidenceFake{}
			p := auth.Principal{Subject: "actor", TenantID: tc.tenant, Environment: tc.env, ApplicationID: "client", Scopes: map[string]struct{}{tc.permission: {}}}
			r := httptest.NewRequest("POST", "/v1/documents/doc/evidence-verification", strings.NewReader(tc.body))
			r.SetPathValue("id", "doc")
			r.Header.Set("X-Tenant-Id", "tenant-b")
			r = r.WithContext(context.WithValue(r.Context(), principalKey, p))
			w := httptest.NewRecorder()
			evidenceHandler(f, "sandbox")(w, r)
			if w.Code != tc.want {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			if tc.want != 200 && f.calls != 0 {
				t.Fatal("unauthorised lookup")
			}
			if tc.want == 200 && f.scope.TenantID != "tenant-a" {
				t.Fatal("untrusted tenant override")
			}
		})
	}
}
