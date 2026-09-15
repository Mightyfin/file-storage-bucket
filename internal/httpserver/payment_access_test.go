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

func TestPaymentGrantRequiresExactOwnerResponse(t *testing.T) {
	for _, mode := range []string{"valid", "wrong-tenant", "wrong-environment", "wrong-payment", "wrong-document", "wrong-digest", "wrong-intent", "wrong-actor", "missing-party", "redirect", "unavailable", "trailing-json"} {
		t.Run(mode, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/internal/manual-payments/mpay_one/document-access" || r.Header.Get("Authorization") != "Bearer staff" {
					t.Error("incorrect owner request")
				}
				var in map[string]string
				if json.NewDecoder(r.Body).Decode(&in) != nil || in["tenant_id"] != "green" || in["intent"] != "verify" || in["document_id"] != "doc_one" {
					t.Error("incorrect scope")
				}
				g := paymentGrant{PaymentID: "mpay_one", TenantID: "green", Environment: "sandbox", PartyID: "party_one", Actor: "staff_one", Intent: "verify", DocumentID: "doc_one", SHA256: strings.Repeat("a", 64)}
				switch mode {
				case "wrong-tenant":
					g.TenantID = "other"
				case "wrong-environment":
					g.Environment = "production"
				case "wrong-payment":
					g.PaymentID = "mpay_other"
				case "wrong-document":
					g.DocumentID = "doc_other"
				case "wrong-digest":
					g.SHA256 = strings.Repeat("b", 64)
				case "wrong-intent":
					g.Intent = "upload"
				case "wrong-actor":
					g.Actor = "someone_else"
				case "missing-party":
					g.PartyID = ""
				case "redirect":
					w.Header().Set("Location", "/redirect")
					w.WriteHeader(302)
					return
				case "unavailable":
					w.WriteHeader(503)
					return
				}
				json.NewEncoder(w).Encode(g)
				if mode == "trailing-json" {
					w.Write([]byte("{}"))
				}
			}))
			defer upstream.Close()
			r := httptest.NewRequest("POST", "/verify?sha256="+strings.Repeat("a", 64), nil)
			r.SetPathValue("tenant", "green")
			r.SetPathValue("payment", "mpay_one")
			r.SetPathValue("id", "doc_one")
			r.Header.Set("Authorization", "Bearer staff")
			r.Header.Set("X-Tenant-Id", "attacker")
			r = r.WithContext(context.WithValue(r.Context(), principalKey, auth.Principal{Subject: "staff_one", Environment: "sandbox", AuthorizedParty: "ops"}))
			w := httptest.NewRecorder()
			sc, _, ok := authorizePayment(w, r, upstream.URL, "sandbox", "verify")
			if ok != (mode == "valid") {
				t.Fatalf("mode %s code %d: %s", mode, w.Code, w.Body.String())
			}
			if ok && (sc.TenantID != "green" || sc.CorrelationID != "mpay_one" || w.Header().Get("Cache-Control") != "no-store") {
				t.Fatal("scope/header lost")
			}
		})
	}
}

func TestTenantCannotUseManualPaymentDocuments(t *testing.T) {
	r := httptest.NewRequest("POST", "/upload", nil)
	r.SetPathValue("tenant", "green")
	r.SetPathValue("payment", "mpay_one")
	r = r.WithContext(context.WithValue(r.Context(), principalKey, auth.Principal{Subject: "tenant-user", TenantID: "green", Environment: "sandbox", AuthorizedParty: "ops"}))
	w := httptest.NewRecorder()
	_, _, ok := authorizePayment(w, r, "http://127.0.0.1:1", "sandbox", "upload")
	if ok || w.Code != 403 {
		t.Fatal("tenant granted staff document access", w.Code)
	}
}
