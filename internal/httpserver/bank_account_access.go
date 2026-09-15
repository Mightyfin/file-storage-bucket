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

type bankAccountGrant struct {
	AccountID   string `json:"account_id"`
	Environment string `json:"environment"`
	TenantID    string `json:"tenant_id"`
	OwnerType   string `json:"owner_type"`
	OwnerID     string `json:"owner_id"`
	Actor       string `json:"actor"`
	Intent      string `json:"intent"`
	DocumentID  string `json:"document_id"`
	SHA256      string `json:"sha256"`
}

func authorizeBankAccount(w http.ResponseWriter, r *http.Request, base, environment, intent string) (documents.Scope, bankAccountGrant, bool) {
	fail := func(status int, code string) (documents.Scope, bankAccountGrant, bool) {
		problem(w, status, code)
		return documents.Scope{}, bankAccountGrant{}, false
	}
	w.Header().Set("Cache-Control", "no-store")
	p, ok := r.Context().Value(principalKey).(auth.Principal)
	account, id := r.PathValue("account"), r.PathValue("id")
	if !ok || p.Subject == "" || p.TenantID != "" || p.ApplicationID != "" || p.AuthorizedParty == "" || p.Environment != environment || (environment != "sandbox" && environment != "production") || account == "" || len(account) > 128 || strings.ContainsAny(account, "/\\?#") {
		return fail(403, "bank_account_access_denied")
	}
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return fail(400, "explicit_bank_account_scope_required")
	}
	digest := ""
	if values, exists := q["sha256"]; exists {
		if len(values) != 1 {
			return fail(400, "invalid_request")
		}
		digest = values[0]
		q.Del("sha256")
	}
	tenant := ""
	valid := len(q) == 1
	if values, exists := q["tenant_id"]; exists {
		valid = valid && len(values) == 1 && values[0] != "" && strings.TrimSpace(values[0]) == values[0] && len(values[0]) <= 128
		if valid {
			tenant = values[0]
		}
	} else {
		values := q["owner_scope"]
		valid = valid && len(values) == 1 && values[0] == "lender"
	}
	if !valid {
		return fail(400, "explicit_bank_account_scope_required")
	}
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fail(503, "bank_account_authorization_unavailable")
	}
	body, _ := json.Marshal(map[string]string{"intent": intent, "document_id": id, "sha256": digest})
	req, err := http.NewRequestWithContext(r.Context(), "POST", strings.TrimRight(base, "/")+"/v1/internal/bank-accounts/"+url.PathEscape(account)+"/document-access?"+q.Encode(), bytes.NewReader(body))
	if err != nil {
		return fail(503, "bank_account_authorization_unavailable")
	}
	req.Header.Set("Authorization", r.Header.Get("Authorization"))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		return fail(503, "bank_account_authorization_unavailable")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		status := res.StatusCode
		if status != 403 && status != 404 && status != 409 && status != 422 {
			status = 503
		}
		return fail(status, "bank_account_access_denied")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 8193))
	var g bankAccountGrant
	if err != nil || len(data) > 8192 || json.Unmarshal(data, &g) != nil || g.AccountID != account || g.Environment != environment || g.TenantID != tenant || g.Actor != p.Subject || g.Intent != intent || g.DocumentID != id || g.SHA256 != digest || g.OwnerID == "" || len(g.OwnerID) > 128 || strings.TrimSpace(g.OwnerID) != g.OwnerID || !((tenant == "" && g.OwnerType == "legal_entity") || (tenant != "" && g.OwnerType == "party")) {
		return fail(503, "invalid_bank_account_authorization")
	}
	sc := scope(r, p)
	sc.TenantID = g.TenantID
	sc.CorrelationID = g.AccountID
	sc.BankAccountReference = g.AccountID
	sc.BankAccountOwnerType = strings.ToUpper(g.OwnerType)
	sc.BankAccountOwnerID = g.OwnerID
	return sc, g, true
}

func registerBankAccountRoutes(mux *http.ServeMux, s *documents.Service, base, environment string) {
	prefix := "/v1/bank-account-documents/{account}/documents"
	authorize := func(w http.ResponseWriter, r *http.Request, intent string) (documents.Scope, bankAccountGrant, bool) {
		return authorizeBankAccount(w, r, base, environment, intent)
	}
	mux.HandleFunc("POST "+prefix+"/upload-sessions", func(w http.ResponseWriter, r *http.Request) {
		sc, g, ok := authorize(w, r, "upload")
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
		if decode(r, &in) != nil {
			problem(w, 400, "invalid_request")
			return
		}
		party := ""
		if g.OwnerType == "party" {
			party = g.OwnerID
		}
		doc, _, err := s.Create(r.Context(), sc, documents.CreateInput{PartyID: party, OwnerType: sc.BankAccountOwnerType, OwnerID: g.OwnerID, SourceReference: g.AccountID, DocumentType: "bank_account_evidence", Purpose: "bank_account_verification", Classification: "RESTRICTED", Filename: in.Filename, ContentType: in.ContentType, Size: in.Size, SHA256: in.SHA256, RetentionCategory: "financial_transaction", IdempotencyKey: r.Header.Get("Idempotency-Key")})
		if handle(w, err) {
			return
		}
		write(w, 201, map[string]any{"document": doc})
	})
	mux.HandleFunc("GET "+prefix+"/{id}", func(w http.ResponseWriter, r *http.Request) {
		sc, g, ok := authorize(w, r, "read")
		if !ok {
			return
		}
		doc, err := s.BankAccountDocument(r.Context(), sc, g.DocumentID)
		if handle(w, err) {
			return
		}
		write(w, 200, doc)
	})
	mux.HandleFunc("PUT "+prefix+"/{id}/content", func(w http.ResponseWriter, r *http.Request) {
		sc, g, ok := authorize(w, r, "complete")
		if !ok {
			return
		}
		_, err := s.BankAccountDocument(r.Context(), sc, g.DocumentID)
		if handle(w, err) {
			return
		}
		doc, err := s.UploadContent(r.Context(), sc, g.DocumentID, http.MaxBytesReader(w, r.Body, 50<<20))
		if handle(w, err) {
			return
		}
		write(w, 202, doc)
	})
	mux.HandleFunc("GET "+prefix+"/{id}/content", func(w http.ResponseWriter, r *http.Request) {
		sc, g, ok := authorize(w, r, "download")
		if !ok {
			return
		}
		doc, body, err := s.OpenBankAccountEvidence(r.Context(), sc, g.DocumentID, g.SHA256)
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
		sc, g, ok := authorize(w, r, "verify")
		if !ok {
			return
		}
		doc, err := s.BankAccountEvidence(r.Context(), sc, g.DocumentID, g.SHA256)
		if handle(w, err) {
			return
		}
		write(w, 200, map[string]any{"document": doc, "tenant_id": g.TenantID, "environment": g.Environment, "resource_reference": g.AccountID, "verification": "available_clean_version"})
	})
}
