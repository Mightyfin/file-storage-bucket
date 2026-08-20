package httpserver

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/Mightyfin/file-storage-bucket/internal/auth"
	"github.com/Mightyfin/file-storage-bucket/internal/config"
	"github.com/Mightyfin/file-storage-bucket/internal/documents"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

type key string

const principalKey key = "principal"

type ready interface{ Ping(context.Context) error }

func New(c config.Config, l *slog.Logger, db ready, s *documents.Service, v auth.Verifier) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			problem(w, http.StatusNotFound, "not_found")
			return
		}
		write(w, http.StatusOK, map[string]any{
			"service":     "MightyFin Document Service",
			"status":      "operational",
			"environment": c.Environment,
			"health": map[string]string{
				"live":  "/health/live",
				"ready": "/health/ready",
			},
			"note": "Internal API service; document operations require authenticated API access.",
		})
	})
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) { write(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if db.Ping(ctx) != nil {
			write(w, 503, map[string]string{"status": "not_ready"})
			return
		}
		write(w, 200, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /v1/documents/upload-sessions", func(w http.ResponseWriter, r *http.Request) {
		p, ok := require(w, r, "documents.write")
		if !ok {
			return
		}
		var b struct {
			PartyID           string     `json:"party_id"`
			OwnerType         string     `json:"owner_type"`
			OwnerID           string     `json:"owner_id"`
			SourceReference   string     `json:"source_reference"`
			ConsentReference  string     `json:"consent_reference"`
			DocumentType      string     `json:"document_type"`
			Purpose           string     `json:"purpose"`
			Classification    string     `json:"classification"`
			Filename          string     `json:"filename"`
			ContentType       string     `json:"content_type"`
			Size              int64      `json:"size_bytes"`
			SHA256            string     `json:"sha256"`
			RetentionCategory string     `json:"retention_category"`
			RetainUntil       *time.Time `json:"retain_until"`
		}
		if decode(r, &b) != nil {
			problem(w, 400, "invalid_request")
			return
		}
		d, u, e := s.Create(r.Context(), scope(r, p), documents.CreateInput{PartyID: b.PartyID, OwnerType: b.OwnerType, OwnerID: b.OwnerID, SourceReference: b.SourceReference, ConsentReference: b.ConsentReference, DocumentType: b.DocumentType, Purpose: b.Purpose, Classification: strings.ToUpper(b.Classification), Filename: b.Filename, ContentType: b.ContentType, Size: b.Size, SHA256: b.SHA256, RetentionCategory: b.RetentionCategory, RetainUntil: b.RetainUntil, IdempotencyKey: r.Header.Get("Idempotency-Key")})
		if handle(w, e) {
			return
		}
		write(w, 201, map[string]any{"document": d, "upload": u})
	})
	mux.HandleFunc("POST /v1/documents/{id}/complete", func(w http.ResponseWriter, r *http.Request) {
		p, ok := require(w, r, "documents.write")
		if !ok {
			return
		}
		d, e := s.Complete(r.Context(), scope(r, p), r.PathValue("id"))
		if handle(w, e) {
			return
		}
		write(w, 202, d)
	})
	mux.HandleFunc("PUT /v1/documents/{id}/content", func(w http.ResponseWriter, r *http.Request) {
		p, ok := require(w, r, "documents.write")
		if !ok {
			return
		}
		d, e := s.UploadContent(r.Context(), scope(r, p), r.PathValue("id"), http.MaxBytesReader(w, r.Body, 50<<20))
		if handle(w, e) {
			return
		}
		write(w, 202, d)
	})
	mux.HandleFunc("POST /v1/internal/documents/{id}/scan-result", func(w http.ResponseWriter, r *http.Request) {
		p, ok := require(w, r, "documents.scan")
		if !ok {
			return
		}
		var b struct {
			Outcome string `json:"outcome"`
			Reason  string `json:"reason"`
		}
		if decode(r, &b) != nil {
			problem(w, 400, "invalid_request")
			return
		}
		d, e := s.RecordScan(r.Context(), scope(r, p), r.PathValue("id"), strings.ToLower(strings.TrimSpace(b.Outcome)), strings.TrimSpace(b.Reason))
		if handle(w, e) {
			return
		}
		write(w, 200, d)
	})
	mux.HandleFunc("POST /v1/documents/{id}/download-session", func(w http.ResponseWriter, r *http.Request) {
		p, ok := require(w, r, "documents.read")
		if !ok {
			return
		}
		u, e := s.Download(r.Context(), scope(r, p), r.PathValue("id"))
		if handle(w, e) {
			return
		}
		write(w, 200, u)
	})
	h := security(authenticate(c.AuthMode == "disabled", c.Environment, v, l, mux))
	return &http.Server{Addr: c.HTTPAddress, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second}
}
func authenticate(disabled bool, defaultEnvironment string, v auth.Verifier, l *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") {
			next.ServeHTTP(w, r)
			return
		}
		if disabled {
			subject := r.Header.Get("X-Local-Subject")
			if subject == "" {
				subject = "local-document-developer"
			}
			p := auth.Principal{Subject: subject, TenantID: value(r.Header.Get("X-Tenant-Id"), "local-test"), Environment: value(r.Header.Get("X-Environment"), defaultEnvironment), ApplicationID: value(r.Header.Get("X-Application-Id"), "local-document-client"), Scopes: map[string]struct{}{"documents.write": {}, "documents.read": {}, "documents.scan": {}}}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
			return
		}
		scheme, token, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			problem(w, 401, "unauthorized")
			return
		}
		p, e := v.Verify(r.Context(), token)
		if e != nil {
			l.Error("auth verify failed", "path", r.URL.Path, "error", e.Error())
		}
		if e != nil {
			problem(w, 401, "unauthorized")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey, p)))
	})
}
func require(w http.ResponseWriter, r *http.Request, scope string) (auth.Principal, bool) {
	p, ok := r.Context().Value(principalKey).(auth.Principal)
	if !ok {
		problem(w, 401, "unauthorized")
		return p, false
	}
	if !p.HasScope(scope) {
		problem(w, 403, "insufficient_scope")
		return p, false
	}
	return p, true
}
func scope(r *http.Request, p auth.Principal) documents.Scope {
	cor := r.Header.Get("X-Correlation-Id")
	if cor == "" {
		cor = "cor_missing"
	}
	// Only machine application credentials carry application_id - a human
	// console session has none, so fall back to azp (the OAuth client the
	// session belongs to, e.g. "efaas-console") rather than leaving this
	// required field empty and rejecting every human-initiated upload.
	return documents.Scope{p.TenantID, p.Environment, p.Subject, value(p.ApplicationID, p.AuthorizedParty), cor}
}
func decode(r *http.Request, v any) error {
	d := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return errors.New("request body must contain exactly one JSON value")
	}
	return nil
}
func handle(w http.ResponseWriter, e error) bool {
	if e == nil {
		return false
	}
	if errors.Is(e, documents.ErrNotFound) {
		problem(w, 404, "not_found")
	} else if errors.Is(e, documents.ErrConflict) {
		problem(w, 409, "conflict")
	} else {
		problem(w, 500, "internal_error")
	}
	return true
}
func security(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, code string) {
	write(w, status, map[string]any{"error": map[string]string{"code": code}})
}
func value(v, f string) string {
	if strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return f
}
