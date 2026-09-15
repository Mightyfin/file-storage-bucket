package documents

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

var ErrEvidenceScope = errors.New("explicit evidence scope required")

// Evidence verifies a PARTY-owned immutable document version. It does not grant
// case access or certify document contents. The case owner must authorise binding.
// Unlike legacy get(), this method never derives or defaults tenant/environment.
func (s *Service) Evidence(ctx context.Context, scope Scope, id, partyID, digest string) (Document, error) {
	return s.verifyEvidence(ctx, scope, id, partyID, digest, "")
}

// ResourceEvidence additionally binds the version to its upload source record.
// Callers must derive resourceReference from an authorized payment/case record.
func (s *Service) ResourceEvidence(ctx context.Context, scope Scope, id, partyID, digest, resourceReference string) (Document, error) {
	if strings.TrimSpace(resourceReference) == "" || len(resourceReference) > 128 {
		return Document{}, ErrConflict
	}
	return s.verifyEvidence(ctx, scope, id, partyID, digest, resourceReference)
}

func (s *Service) verifyEvidence(ctx context.Context, scope Scope, id, partyID, digest, resourceReference string) (Document, error) {
	if strings.TrimSpace(scope.TenantID) == "" || strings.TrimSpace(scope.Environment) == "" || strings.TrimSpace(scope.Subject) == "" || strings.TrimSpace(scope.ApplicationID) == "" {
		return Document{}, ErrEvidenceScope
	}
	if strings.TrimSpace(id) == "" || strings.TrimSpace(partyID) == "" || !shaPattern.MatchString(digest) {
		return Document{}, ErrConflict
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Document{}, err
	}
	defer tx.Rollback(ctx)
	var d Document
	err = tx.QueryRow(ctx, `SELECT public_id,party_id,owner_type,owner_id,status,scan_status,document_type,purpose,classification,content_type,size_bytes,sha256_hex,created_at FROM documents
 WHERE public_id=$1 AND tenant_id=$2 AND environment=$3 AND owner_type='PARTY' AND owner_id=$4 AND party_id=$4 AND ($5='' OR source_reference=$5) FOR SHARE`, id, scope.TenantID, scope.Environment, partyID, resourceReference).Scan(&d.ID, &d.PartyID, &d.OwnerType, &d.OwnerID, &d.Status, &d.ScanStatus, &d.DocumentType, &d.Purpose, &d.Classification, &d.ContentType, &d.Size, &d.SHA256, &d.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, ErrNotFound
	}
	if err != nil {
		return Document{}, err
	}
	if d.Status != "available" || d.ScanStatus != "clean" || d.SHA256 != digest {
		return Document{}, ErrConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO document_audit_events(document_id,action,actor_subject,actor_application,correlation_id) SELECT id,'evidence_version_checked',$2,$3,$4 FROM documents WHERE public_id=$1`, id, scope.Subject, scope.ApplicationID, scope.CorrelationID)
	if err != nil {
		return Document{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Document{}, err
	}
	return d, nil
}
