package httpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Mightyfin/file-storage-bucket/internal/auth"
)

func TestBankAccountGrantValidation(t *testing.T) {
	for _, lender := range []bool{false, true} {
		for _, mode := range []string{"valid", "tenant", "environment", "case", "actor", "document", "digest", "intent", "owner-type", "owner-empty", "redirect", "unavailable", "trailing", "oversize"} {
			t.Run(mode+map[bool]string{true: "-lender", false: "-participant"}[lender], func(t *testing.T) {
				tenant, ownerType, query := "green", "party", "tenant_id=green"
				if lender {
					tenant, ownerType, query = "", "legal_entity", "owner_scope=lender"
				}
				sha := strings.Repeat("a", 64)
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Method != "POST" || r.URL.Path != "/v1/internal/bank-accounts/bac_one/document-access" || r.URL.RawQuery != query || r.Header.Get("Authorization") != "Bearer staff" {
						t.Error("incorrect grant request")
					}
					var input map[string]string
					if json.NewDecoder(r.Body).Decode(&input) != nil || len(input) != 3 || input["intent"] != "verify" || input["document_id"] != "doc_one" || input["sha256"] != sha {
						t.Error("wrong request binding")
					}
					g := bankAccountGrant{AccountID: "bac_one", TenantID: tenant, Environment: "sandbox", OwnerType: ownerType, OwnerID: "owner_one", Actor: "staff_one", Intent: "verify", DocumentID: "doc_one", SHA256: sha}
					switch mode {
					case "tenant":
						g.TenantID = "other"
					case "environment":
						g.Environment = "production"
					case "case":
						g.AccountID = "bac_other"
					case "actor":
						g.Actor = "other"
					case "document":
						g.DocumentID = "other"
					case "digest":
						g.SHA256 = strings.Repeat("b", 64)
					case "intent":
						g.Intent = "download"
					case "owner-type":
						g.OwnerType = "TENANT"
					case "owner-empty":
						g.OwnerID = ""
					case "redirect":
						w.Header().Set("Location", "/redirect")
						w.WriteHeader(302)
						return
					case "unavailable":
						w.WriteHeader(503)
						return
					case "oversize":
						w.Write([]byte(strings.Repeat(" ", 8193)))
						return
					}
					json.NewEncoder(w).Encode(g)
					if mode == "trailing" {
						w.Write([]byte("{}"))
					}
				}))
				defer server.Close()
				r := httptest.NewRequest("POST", "/verify?"+query+"&sha256="+sha, nil)
				r.SetPathValue("account", "bac_one")
				r.SetPathValue("id", "doc_one")
				r.Header.Set("Authorization", "Bearer staff")
				r.Header.Set("X-Tenant-Id", "attacker")
				r = r.WithContext(context.WithValue(r.Context(), principalKey, auth.Principal{Subject: "staff_one", Environment: "sandbox", AuthorizedParty: "ops"}))
				w := httptest.NewRecorder()
				sc, _, ok := authorizeBankAccount(w, r, server.URL, "sandbox", "verify")
				if ok != (mode == "valid") {
					t.Fatal(mode, w.Code, w.Body.String())
				}
				if ok && (sc.BankAccountReference != "bac_one" || sc.BankAccountOwnerID != "owner_one" || sc.BankAccountOwnerType != strings.ToUpper(ownerType) || sc.TenantID != tenant || sc.ApplicationID != "ops" || sc.PaymentReference != "" || sc.StatementReference != "") {
					t.Fatal("incorrect trusted scope", sc)
				}
			})
		}
	}
}

func TestBankAccountBadCallerFailsBeforeUpstream(t *testing.T) {
	for _, tc := range []struct{ query, tenant, app, env string }{
		{"tenant_id=green", "green", "", "sandbox"},
		{"tenant_id=green", "", "machine", "sandbox"},
		{"tenant_id=green", "", "", "production"},
		{"tenant_id=green&owner_scope=lender", "", "", "sandbox"},
		{"tenant_id=green&tenant_id=other", "", "", "sandbox"},
		{"owner_scope=other", "", "", "sandbox"},
		{"tenant_id=green&owner_id=forged", "", "", "sandbox"},
		{"tenant_id=green&sha256=a&sha256=b", "", "", "sandbox"},
		{"tenant_id=green&bad=%zz", "", "", "sandbox"},
	} {
		r := httptest.NewRequest("POST", "/upload?"+tc.query, nil)
		r.SetPathValue("account", "bac_one")
		r = r.WithContext(context.WithValue(r.Context(), principalKey, auth.Principal{Subject: "staff", AuthorizedParty: "ops", Environment: tc.env, TenantID: tc.tenant, ApplicationID: tc.app}))
		w := httptest.NewRecorder()
		_, _, ok := authorizeBankAccount(w, r, "http://127.0.0.1:1", "sandbox", "upload")
		if ok || (w.Code != 400 && w.Code != 403) {
			t.Fatal("request reached unavailable upstream", tc, w.Code)
		}
	}
}
