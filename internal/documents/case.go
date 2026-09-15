package documents

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"io"
)

func (s *Service) CaseUploads(ctx context.Context, scope Scope, application, party, after string) ([]Document, error) {
	if scope.TenantID == "" || scope.Environment == "" || scope.Subject == "" || scope.ApplicationID == "" || application == "" || party == "" {
		return nil, ErrEvidenceScope
	}
	rows, err := s.db.Query(ctx, `SELECT public_id,party_id,owner_type,owner_id,status,scan_status,document_type,purpose,classification,content_type,size_bytes,sha256_hex,created_at FROM documents WHERE tenant_id=$1 AND environment=$2 AND source_reference=$3 AND owner_type='PARTY' AND owner_id=$4 AND party_id=$4 AND public_id>$5 ORDER BY public_id LIMIT 51`, scope.TenantID, scope.Environment, application, party, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Document{}
	for rows.Next() {
		var d Document
		if err = rows.Scan(&d.ID, &d.PartyID, &d.OwnerType, &d.OwnerID, &d.Status, &d.ScanStatus, &d.DocumentType, &d.Purpose, &d.Classification, &d.ContentType, &d.Size, &d.SHA256, &d.CreatedAt); err != nil {
			return nil, err
		}
		if d.Purpose != "manual_bank_payment" || scope.PaymentReference == application {
			out = append(out, d)
		}
	}
	return out, rows.Err()
}

// CaseUpload only reads uploads explicitly created for this case. The caller
// must first obtain the scope and party from the owning decision service.
func (s *Service) CaseUpload(ctx context.Context, scope Scope, application, party, id string) (Document, error) {
	if scope.TenantID == "" || scope.Environment == "" || scope.Subject == "" || scope.ApplicationID == "" || application == "" || party == "" {
		return Document{}, ErrEvidenceScope
	}
	var found bool
	err := s.db.QueryRow(ctx, `SELECT true FROM documents WHERE public_id=$1 AND tenant_id=$2 AND environment=$3 AND source_reference=$4 AND owner_type='PARTY' AND owner_id=$5 AND party_id=$5`, id, scope.TenantID, scope.Environment, application, party).Scan(&found)
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, ErrNotFound
	}
	if err != nil {
		return Document{}, err
	}
	return s.get(ctx, scope, id)
}

// OpenEvidence does not expose a signed object URL. Both case binding (at the
// HTTP boundary) and current clean document version must pass before opening.
func (s *Service) OpenEvidence(ctx context.Context, scope Scope, id, party, digest string) (Document, io.ReadCloser, error) {
	d, err := s.Evidence(ctx, scope, id, party, digest)
	if err != nil {
		return Document{}, nil, err
	}
	stored, err := s.get(ctx, scope, id)
	if err != nil {
		return Document{}, nil, err
	}
	opener, ok := s.objects.(interface {
		Open(context.Context, string) (io.ReadCloser, error)
	})
	if !ok {
		return Document{}, nil, errors.New("object streaming unavailable")
	}
	_, err = s.db.Exec(ctx, `INSERT INTO document_audit_events(document_id,action,actor_subject,actor_application,correlation_id) SELECT id,'case_download_authorized',$2,$3,$4 FROM documents WHERE public_id=$1 AND tenant_id=$5 AND environment=$6`, id, scope.Subject, scope.ApplicationID, scope.CorrelationID, scope.TenantID, scope.Environment)
	if err != nil {
		return Document{}, nil, err
	}
	body, err := opener.Open(ctx, stored.objectKey)
	return d, body, err
}
