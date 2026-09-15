package httpserver

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Mightyfin/file-storage-bucket/internal/auth"
	"github.com/Mightyfin/file-storage-bucket/internal/documents"
)

type paymentGrant struct {
	PaymentID   string `json:"payment_id"`
	TenantID    string `json:"tenant_id"`
	Environment string `json:"environment"`
	PartyID     string `json:"party_id"`
	Actor       string `json:"actor"`
	Intent      string `json:"intent"`
	DocumentID  string `json:"document_id"`
	SHA256      string `json:"sha256"`
}

// Staff access is decided by Payment Rails against the actual record and role.
// No tenant header, file owner supplied by a browser, or platform-wide fallback.
func authorizePayment(w http.ResponseWriter, r *http.Request, base, environment, intent string) (documents.Scope, paymentGrant, bool) {
	p, ok := r.Context().Value(principalKey).(auth.Principal)
	tenant, payment, id := r.PathValue("tenant"), r.PathValue("payment"), r.PathValue("id")
	digest := r.URL.Query().Get("sha256")
	if !ok || p.Subject == "" || p.TenantID != "" || p.ApplicationID != "" || p.Environment != environment || (environment != "sandbox" && environment != "production") || tenant == "" || payment == "" || strings.ContainsAny(payment, "/\\?#") {
		problem(w, 403, "payment_access_denied")
		return documents.Scope{}, paymentGrant{}, false
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		problem(w, 503, "payment_authorization_unavailable")
		return documents.Scope{}, paymentGrant{}, false
	}
	body, _ := json.Marshal(map[string]string{"tenant_id": tenant, "intent": intent, "document_id": id, "sha256": digest})
	req, err := http.NewRequestWithContext(r.Context(), "POST", strings.TrimRight(base, "/")+"/v1/internal/manual-payments/"+url.PathEscape(payment)+"/document-access", bytes.NewReader(body))
	if err != nil {
		problem(w, 503, "payment_authorization_unavailable")
		return documents.Scope{}, paymentGrant{}, false
	}
	req.Header.Set("Authorization", r.Header.Get("Authorization"))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		problem(w, 503, "payment_authorization_unavailable")
		return documents.Scope{}, paymentGrant{}, false
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		status := res.StatusCode
		if status != 403 && status != 404 && status != 409 && status != 422 {
			status = 503
		}
		problem(w, status, "payment_access_denied")
		return documents.Scope{}, paymentGrant{}, false
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 8193))
	var grant paymentGrant
	if err != nil || len(data) > 8192 || json.Unmarshal(data, &grant) != nil || grant.PaymentID != payment || grant.TenantID != tenant || grant.Environment != environment || grant.PartyID == "" || grant.Actor != p.Subject || grant.Intent != intent || grant.DocumentID != id || grant.SHA256 != digest {
		problem(w, 503, "invalid_payment_authorization")
		return documents.Scope{}, paymentGrant{}, false
	}
	sc := scope(r, p)
	sc.TenantID = grant.TenantID
	sc.CorrelationID = grant.PaymentID
	sc.PaymentReference = grant.PaymentID
	if sc.ApplicationID == "" {
		problem(w, 403, "payment_access_denied")
		return documents.Scope{}, paymentGrant{}, false
	}
	w.Header().Set("Cache-Control", "no-store")
	return sc, grant, true
}

func registerPaymentRoutes(mux *http.ServeMux, s *documents.Service, base, environment string) {
	prefix := "/v1/manual-payments/tenants/{tenant}/payments/{payment}/documents"
	mux.HandleFunc("POST "+prefix+"/upload-sessions", func(w http.ResponseWriter, r *http.Request) {
		sc, g, ok := authorizePayment(w, r, base, environment, "upload")
		if !ok {
			return
		}
		var in struct {
			Filename    string `json:"filename"`
			ContentType string `json:"content_type"`
			Size        int64  `json:"size_bytes"`
			SHA256      string `json:"sha256"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		d := json.NewDecoder(r.Body)
		d.DisallowUnknownFields()
		if d.Decode(&in) != nil || d.Decode(&struct{}{}) != io.EOF {
			problem(w, 400, "invalid_request")
			return
		}
		doc, _, err := s.Create(r.Context(), sc, documents.CreateInput{PartyID: g.PartyID, OwnerType: "PARTY", OwnerID: g.PartyID, SourceReference: g.PaymentID, DocumentType: "bank_payment_evidence", Purpose: "manual_bank_payment", Classification: "RESTRICTED", Filename: in.Filename, ContentType: in.ContentType, Size: in.Size, SHA256: in.SHA256, RetentionCategory: "financial_transaction", IdempotencyKey: r.Header.Get("Idempotency-Key")})
		if handle(w, err) {
			return
		}
		write(w, 201, map[string]any{"document": doc})
	})
	mux.HandleFunc("GET "+prefix+"/{id}", func(w http.ResponseWriter, r *http.Request) {
		sc, g, ok := authorizePayment(w, r, base, environment, "read")
		if !ok {
			return
		}
		doc, err := s.CaseUpload(r.Context(), sc, g.PaymentID, g.PartyID, g.DocumentID)
		if handle(w, err) {
			return
		}
		write(w, 200, doc)
	})
	mux.HandleFunc("PUT "+prefix+"/{id}/content", func(w http.ResponseWriter, r *http.Request) {
		sc, g, ok := authorizePayment(w, r, base, environment, "upload")
		if !ok {
			return
		}
		if _, err := s.CaseUpload(r.Context(), sc, g.PaymentID, g.PartyID, g.DocumentID); handle(w, err) {
			return
		}
		doc, err := s.UploadContent(r.Context(), sc, g.DocumentID, http.MaxBytesReader(w, r.Body, 50<<20))
		if handle(w, err) {
			return
		}
		write(w, 202, doc)
	})
	mux.HandleFunc("GET "+prefix+"/{id}/content", func(w http.ResponseWriter, r *http.Request) {
		sc, g, ok := authorizePayment(w, r, base, environment, "download")
		if !ok {
			return
		}
		if _, err := s.ResourceEvidence(r.Context(), sc, g.DocumentID, g.PartyID, g.SHA256, g.PaymentID); handle(w, err) {
			return
		}
		doc, body, err := s.OpenEvidence(r.Context(), sc, g.DocumentID, g.PartyID, g.SHA256)
		if handle(w, err) {
			return
		}
		defer body.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		io.Copy(w, io.LimitReader(body, doc.Size))
	})
	mux.HandleFunc("POST "+prefix+"/{id}/evidence-verification", func(w http.ResponseWriter, r *http.Request) {
		sc, g, ok := authorizePayment(w, r, base, environment, "verify")
		if !ok {
			return
		}
		doc, err := s.ResourceEvidence(r.Context(), sc, g.DocumentID, g.PartyID, g.SHA256, g.PaymentID)
		if handle(w, err) {
			return
		}
		write(w, 200, map[string]any{"document": doc, "tenant_id": g.TenantID, "environment": g.Environment, "resource_reference": g.PaymentID, "verification": "available_clean_version"})
	})
}
