package documents

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"io"
	"strings"
)

// These fields are populated only by the owner-service grant resolver. They
// must never be populated from ordinary document request bodies/headers.
func validBankAccountScope(s Scope) bool {
	if strings.TrimSpace(s.BankAccountReference) == "" || len(s.BankAccountReference) > 128 || strings.TrimSpace(s.BankAccountOwnerID) == "" || len(s.BankAccountOwnerID) > 128 || s.Subject == "" || s.ApplicationID == "" || (s.Environment != "sandbox" && s.Environment != "production") {
		return false
	}
	return (s.BankAccountOwnerType == "PARTY" && s.TenantID != "") || (s.BankAccountOwnerType == "LEGAL_ENTITY" && s.TenantID == "")
}
func (s *Service) BankAccountDocument(ctx context.Context, scope Scope, id string) (Document, error) {
	if !validBankAccountScope(scope) {
		return Document{}, ErrEvidenceScope
	}
	var found bool
	err := s.db.QueryRow(ctx, `SELECT true FROM documents WHERE public_id=$1 AND tenant_id=$2 AND environment=$3 AND source_reference=$4 AND owner_type=$5 AND owner_id=$6 AND purpose='bank_account_verification'`, id, scope.TenantID, scope.Environment, scope.BankAccountReference, scope.BankAccountOwnerType, scope.BankAccountOwnerID).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, ErrNotFound
	}
	if err != nil {
		return Document{}, err
	}
	return s.get(ctx, scope, id)
}
func (s *Service) BankAccountEvidence(ctx context.Context, scope Scope, id, digest string) (Document, error) {
	if !validBankAccountScope(scope) || !shaPattern.MatchString(digest) {
		return Document{}, ErrEvidenceScope
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return Document{}, err
	}
	defer tx.Rollback(ctx)
	var d Document
	err = tx.QueryRow(ctx, `SELECT public_id,coalesce(party_id,''),owner_type,owner_id,status,scan_status,document_type,purpose,classification,content_type,size_bytes,sha256_hex,created_at FROM documents WHERE public_id=$1 AND tenant_id=$2 AND environment=$3 AND source_reference=$4 AND owner_type=$5 AND owner_id=$6 AND purpose='bank_account_verification' FOR SHARE`, id, scope.TenantID, scope.Environment, scope.BankAccountReference, scope.BankAccountOwnerType, scope.BankAccountOwnerID).Scan(&d.ID, &d.PartyID, &d.OwnerType, &d.OwnerID, &d.Status, &d.ScanStatus, &d.DocumentType, &d.Purpose, &d.Classification, &d.ContentType, &d.Size, &d.SHA256, &d.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	if d.Status != "available" || d.ScanStatus != "clean" || d.SHA256 != digest {
		return d, ErrConflict
	}
	_, err = tx.Exec(ctx, `INSERT INTO document_audit_events(document_id,action,actor_subject,actor_application,correlation_id) SELECT id,'bank_account_evidence_checked',$2,$3,$4 FROM documents WHERE public_id=$1`, id, scope.Subject, scope.ApplicationID, scope.BankAccountReference)
	if err != nil {
		return d, err
	}
	return d, tx.Commit(ctx)
}
func (s *Service) OpenBankAccountEvidence(ctx context.Context, scope Scope, id, digest string) (Document, io.ReadCloser, error) {
	d, err := s.BankAccountEvidence(ctx, scope, id, digest)
	if err != nil {
		return d, nil, err
	}
	stored, err := s.BankAccountDocument(ctx, scope, id)
	if err != nil {
		return d, nil, err
	}
	opener, ok := s.objects.(interface {
		Open(context.Context, string) (io.ReadCloser, error)
	})
	if !ok {
		return d, nil, errors.New("object streaming unavailable")
	}
	_, err = s.db.Exec(ctx, `INSERT INTO document_audit_events(document_id,action,actor_subject,actor_application,correlation_id) SELECT id,'bank_account_download_authorized',$2,$3,$4 FROM documents WHERE public_id=$1`, id, scope.Subject, scope.ApplicationID, scope.BankAccountReference)
	if err != nil {
		return d, nil, err
	}
	body, err := opener.Open(ctx, stored.objectKey)
	return d, body, err
}
