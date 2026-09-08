package httpserver

import (
	"context"
	"encoding/json"
	"github.com/Mightyfin/file-storage-bucket/internal/auth"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCaseAuthorizationDoesNotTrustCallerScope(t *testing.T) {
	for _, tc := range []struct {
		name, tenant, environment, party, actor string
		status, want                            int
	}{
		{"valid", "t", "sandbox", "p", "actor", 200, 200},
		{"wrong tenant", "other", "sandbox", "p", "actor", 200, 503},
		{"wrong environment", "t", "production", "p", "actor", 200, 503},
		{"missing party", "t", "sandbox", "", "actor", 200, 503},
		{"wrong actor", "t", "sandbox", "p", "someone", 200, 503},
		{"denied", "t", "sandbox", "p", "actor", 403, 403},
		{"missing", "t", "sandbox", "p", "actor", 404, 404},
		{"unverified", "t", "sandbox", "p", "actor", 409, 409},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer original-caller" {
					t.Error("original credential not forwarded")
				}
				w.WriteHeader(tc.status)
				json.NewEncoder(w).Encode(caseGrant{ApplicationID: "a", TenantID: tc.tenant, Environment: tc.environment, PartyID: tc.party, Actor: tc.actor, Intent: "download", DocumentID: "d", SHA256: "hash"})
			}))
			defer upstream.Close()
			r := httptest.NewRequest("GET", "/content?sha256=hash", nil)
			r.SetPathValue("tenant", "t")
			r.SetPathValue("application", "a")
			r.SetPathValue("id", "d")
			r.Header.Set("Authorization", "Bearer original-caller")
			r.Header.Set("X-Tenant-Id", "attacker")
			r = r.WithContext(context.WithValue(r.Context(), principalKey, auth.Principal{Subject: "actor", Environment: "sandbox", AuthorizedParty: "console"}))
			w := httptest.NewRecorder()
			scoped, _, ok := authorizeCase(w, r, upstream.URL, "sandbox", "download")
			if w.Code != tc.want || ok != (tc.want == 200) {
				t.Fatalf("got %d %v: %s", w.Code, ok, w.Body.String())
			}
			if ok && scoped.TenantID != "t" {
				t.Fatal("trusted unverified scope")
			}
		})
	}
}
