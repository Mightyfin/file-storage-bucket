package httpserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/Mightyfin/file-storage-bucket/internal/auth"
	"github.com/Mightyfin/file-storage-bucket/internal/documents"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type caseGrant struct {
	ApplicationID string `json:"application_id"`
	TenantID      string `json:"tenant_id"`
	Environment   string `json:"environment"`
	PartyID       string `json:"party_id"`
	Intent        string `json:"intent"`
	DocumentID    string `json:"document_id"`
	SHA256        string `json:"sha256"`
	Actor         string `json:"actor"`
}

func authorizeCase(w http.ResponseWriter, r *http.Request, base, environment, intent string) (documents.Scope, caseGrant, bool) {
	p, ok := r.Context().Value(principalKey).(auth.Principal)
	tenant := r.PathValue("tenant")
	if !ok || p.Subject == "" || p.Environment != environment || environment == "" || tenant == "" {
		problem(w, 403, "forbidden")
		return documents.Scope{}, caseGrant{}, false
	}
	if base == "" {
		problem(w, 503, "case_authorization_unavailable")
		return documents.Scope{}, caseGrant{}, false
	}
	application := r.PathValue("application")
	digest := r.URL.Query().Get("sha256")
	body, _ := json.Marshal(map[string]string{"tenant_id": tenant, "intent": intent, "document_id": r.PathValue("id"), "sha256": digest})
	req, err := http.NewRequestWithContext(r.Context(), "POST", strings.TrimRight(base, "/")+"/v1/credit/applications/"+url.PathEscape(application)+"/document-access", bytes.NewReader(body))
	if err != nil {
		problem(w, 503, "case_authorization_unavailable")
		return documents.Scope{}, caseGrant{}, false
	}
	req.Header.Set("Authorization", r.Header.Get("Authorization"))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect denied") }}
	res, err := client.Do(req)
	if err != nil {
		problem(w, 503, "case_authorization_unavailable")
		return documents.Scope{}, caseGrant{}, false
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		status := res.StatusCode
		if status != 403 && status != 404 && status != 409 {
			status = 503
		}
		problem(w, status, "case_access_denied")
		return documents.Scope{}, caseGrant{}, false
	}
	var grant caseGrant
	dec := json.NewDecoder(io.LimitReader(res.Body, 8192))
	if dec.Decode(&grant) != nil || grant.ApplicationID != application || grant.TenantID != tenant || grant.Environment != p.Environment || grant.PartyID == "" || grant.Actor != p.Subject || grant.Intent != intent || grant.DocumentID != r.PathValue("id") || grant.SHA256 != digest {
		problem(w, 503, "invalid_case_authorization")
		return documents.Scope{}, caseGrant{}, false
	}
	scoped := scope(r, p)
	scoped.TenantID = grant.TenantID
	scoped.CorrelationID = application
	if scoped.ApplicationID == "" {
		problem(w, 403, "forbidden")
		return documents.Scope{}, caseGrant{}, false
	}
	return scoped, grant, true
}

func registerCaseRoutes(mux *http.ServeMux, s *documents.Service, base, environment string) {
	prefix := "/v1/credit/tenants/{tenant}/applications/{application}/documents"
	mux.HandleFunc("GET "+prefix, func(w http.ResponseWriter, r *http.Request) {
		scoped, g, ok := authorizeCase(w, r, base, environment, "uploads")
		if !ok {
			return
		}
		after := r.URL.Query().Get("after")
		if len(after) > 128 {
			problem(w, 400, "invalid_cursor")
			return
		}
		rows, err := s.CaseUploads(r.Context(), scoped, g.ApplicationID, g.PartyID, after)
		if handle(w, err) {
			return
		}
		next := ""
		if len(rows) > 50 {
			rows = rows[:50]
			next = rows[49].ID
		}
		write(w, 200, map[string]any{"data": rows, "next_cursor": next})
	})
	mux.HandleFunc("GET "+prefix+"/{id}/content", func(w http.ResponseWriter, r *http.Request) {
		scoped, g, ok := authorizeCase(w, r, base, environment, "download")
		if !ok {
			return
		}
		d, body, err := s.OpenEvidence(r.Context(), scoped, g.DocumentID, g.PartyID, g.SHA256)
		if handle(w, err) {
			return
		}
		defer body.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", "attachment")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Bound streaming to the immutable declared size, without buffering 50MB per viewer.
		io.Copy(w, io.LimitReader(body, d.Size))
	})
	mux.HandleFunc("POST "+prefix+"/upload-sessions", func(w http.ResponseWriter, r *http.Request) {
		scoped, g, ok := authorizeCase(w, r, base, environment, "upload")
		if !ok {
			return
		}
		var in struct {
			DocumentType     string `json:"document_type"`
			Filename         string `json:"filename"`
			ContentType      string `json:"content_type"`
			Size             int64  `json:"size_bytes"`
			SHA256           string `json:"sha256"`
			ConsentReference string `json:"consent_reference"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8192)
		if decode(r, &in) != nil {
			problem(w, 400, "invalid_request")
			return
		}
		d, _, err := s.Create(r.Context(), scoped, documents.CreateInput{PartyID: g.PartyID, OwnerType: "PARTY", OwnerID: g.PartyID, SourceReference: g.ApplicationID, ConsentReference: in.ConsentReference, DocumentType: in.DocumentType, Purpose: "credit_assessment", Classification: "RESTRICTED", Filename: in.Filename, ContentType: in.ContentType, Size: in.Size, SHA256: in.SHA256, RetentionCategory: "credit_application", IdempotencyKey: r.Header.Get("Idempotency-Key")})
		if handle(w, err) {
			return
		}
		write(w, 201, map[string]any{"document": d})
	})
	mux.HandleFunc("GET "+prefix+"/{id}", func(w http.ResponseWriter, r *http.Request) {
		scoped, g, ok := authorizeCase(w, r, base, environment, "uploads")
		if !ok {
			return
		}
		d, err := s.CaseUpload(r.Context(), scoped, g.ApplicationID, g.PartyID, g.DocumentID)
		if handle(w, err) {
			return
		}
		write(w, 200, d)
	})
	mux.HandleFunc("PUT "+prefix+"/{id}/content", func(w http.ResponseWriter, r *http.Request) {
		scoped, g, ok := authorizeCase(w, r, base, environment, "upload")
		if !ok {
			return
		}
		_, err := s.CaseUpload(r.Context(), scoped, g.ApplicationID, g.PartyID, g.DocumentID)
		if handle(w, err) {
			return
		}
		d, err := s.UploadContent(r.Context(), scoped, g.DocumentID, http.MaxBytesReader(w, r.Body, 50<<20))
		if handle(w, err) {
			return
		}
		write(w, 202, d)
	})
}
