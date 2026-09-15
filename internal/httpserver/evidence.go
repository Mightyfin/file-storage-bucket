package httpserver

import (
	"context"
	"net/http"

	"github.com/Mightyfin/file-storage-bucket/internal/documents"
)

type evidenceVerifier interface {
	Evidence(context.Context, documents.Scope, string, string, string) (documents.Document, error)
}

func evidenceHandler(service evidenceVerifier, environment string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := require(w, r, "documents.evidence.verify")
		if !ok {
			return
		}
		sc := scope(r, p)
		if sc.TenantID == "" || sc.Subject == "" || sc.ApplicationID == "" || environment == "" || sc.Environment != environment {
			problem(w, 403, "explicit_evidence_scope_required")
			return
		}
		var in struct {
			PartyID           string  `json:"party_id"`
			SHA256            string  `json:"sha256"`
			ResourceReference *string `json:"resource_reference,omitempty"`
		}
		if decode(r, &in) != nil {
			problem(w, 400, "invalid_request")
			return
		}
		var d documents.Document
		var err error
		if in.ResourceReference != nil {
			resourceService, ok := service.(interface {
				ResourceEvidence(context.Context, documents.Scope, string, string, string, string) (documents.Document, error)
			})
			if !ok {
				problem(w, 503, "resource_evidence_unavailable")
				return
			}
			d, err = resourceService.ResourceEvidence(r.Context(), sc, r.PathValue("id"), in.PartyID, in.SHA256, *in.ResourceReference)
		} else {
			d, err = service.Evidence(r.Context(), sc, r.PathValue("id"), in.PartyID, in.SHA256)
		}
		if handle(w, err) {
			return
		}
		write(w, 200, map[string]any{"document": d, "tenant_id": sc.TenantID, "environment": sc.Environment, "resource_reference": in.ResourceReference, "verification": "available_clean_version", "case_authorization_required": true})
	}
}
