package documents

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/Mightyfin/file-storage-bucket/internal/objectstore"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrNotFound = errors.New("document not found")
var ErrConflict = errors.New("document conflict")
var shaPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Scope struct{ TenantID, Environment, Subject, ApplicationID, CorrelationID string }
type CreateInput struct {
	PartyID, OwnerType, OwnerID, SourceReference, ConsentReference, DocumentType, Purpose, Classification, Filename, ContentType, SHA256, RetentionCategory, IdempotencyKey string
	Size                                                                                                                                int64
	RetainUntil                                                                                                                         *time.Time
}
type Document struct {
	ID                  string    `json:"id"`
	PartyID             string    `json:"party_id"`
	OwnerType           string    `json:"owner_type"`
	OwnerID             string    `json:"owner_id"`
	Status              string    `json:"status"`
	ScanStatus          string    `json:"scan_status"`
	DocumentType        string    `json:"document_type"`
	Purpose             string    `json:"purpose"`
	Classification      string    `json:"classification"`
	ContentType         string    `json:"content_type"`
	Size                int64     `json:"size_bytes"`
	SHA256              string    `json:"sha256"`
	CreatedAt           time.Time `json:"created_at"`
	objectKey, filename string
}
type Party interface {
	Exists(context.Context, string, string, string) error
}
type Objects interface {
	PresignUpload(context.Context, string, string, string, int64, time.Duration) (objectstore.SignedRequest, error)
	Verify(context.Context, string, string, int64) error
	PresignDownload(context.Context, string, string, time.Duration) (objectstore.SignedRequest, error)
}
type Service struct {
	db                     *pgxpool.Pool
	party                  Party
	objects                Objects
	bucket                 string
	uploadTTL, downloadTTL time.Duration
}

func New(db *pgxpool.Pool, p Party, o Objects, bucket string, up, down time.Duration) *Service {
	return &Service{db, p, o, bucket, up, down}
}
func (s *Service) Create(ctx context.Context, scope Scope, in CreateInput) (Document, objectstore.SignedRequest, error) {
	in.Filename = filepath.Base(strings.TrimSpace(in.Filename))
	in.SHA256 = strings.ToLower(strings.TrimSpace(in.SHA256))
	allowedType := map[string]bool{"application/pdf": true, "image/jpeg": true, "image/png": true}
	allowedClass := map[string]bool{"INTERNAL": true, "CONFIDENTIAL": true, "RESTRICTED": true}
	in.IdempotencyKey = strings.TrimSpace(in.IdempotencyKey)
	in.OwnerType = strings.ToUpper(strings.TrimSpace(in.OwnerType))
	in.OwnerID = strings.TrimSpace(in.OwnerID)
	if in.OwnerType == "" && in.PartyID != "" { in.OwnerType, in.OwnerID = "PARTY", in.PartyID }
	allowedOwner := map[string]bool{"PARTY":true,"LEGAL_ENTITY":true,"ORGANISATIONAL_UNIT":true,"CASE":true,"PRODUCT_RESOURCE":true,"REGULATORY_RECORD":true}
	if in.OwnerType == "PARTY" { in.PartyID = in.OwnerID } else { in.PartyID = "" }
	if scope.TenantID == "" || scope.Environment == "" || scope.Subject == "" || scope.ApplicationID == "" || !allowedOwner[in.OwnerType] || in.OwnerID == "" || len(in.OwnerID)>128 || in.DocumentType == "" || in.Purpose == "" || in.RetentionCategory == "" || in.Filename == "" || len(in.Filename) > 255 || in.IdempotencyKey == "" || len(in.IdempotencyKey) > 128 || !allowedType[in.ContentType] || !allowedClass[in.Classification] || in.Size < 1 || in.Size > 50<<20 || !shaPattern.MatchString(in.SHA256) {
		return Document{}, objectstore.SignedRequest{}, ErrConflict
	}
	fingerprintInput := in
	fingerprintInput.IdempotencyKey = ""
	encoded, _ := json.Marshal(fingerprintInput)
	requestHash := fmt.Sprintf("%x", sha256.Sum256(encoded))
	if existing, e := s.getIdempotent(ctx, scope, in.IdempotencyKey, requestHash); e == nil {
		signed, signErr := s.objects.PresignUpload(ctx, existing.objectKey, existing.ContentType, existing.SHA256, existing.Size, s.uploadTTL)
		return existing, signed, signErr
	} else if !errors.Is(e, ErrNotFound) {
		return Document{}, objectstore.SignedRequest{}, e
	}
	if in.OwnerType == "PARTY" { if e := s.party.Exists(ctx, scope.TenantID, scope.Environment, in.PartyID); e != nil {
		return Document{}, objectstore.SignedRequest{}, ErrConflict
	} }
	id := newID("doc")
	key := scope.Environment + "/" + scope.TenantID + "/" + strings.ToLower(in.OwnerType) + "/" + in.OwnerID + "/" + id + "/original"
	expires := time.Now().UTC().Add(s.uploadTTL)
	tx, e := s.db.Begin(ctx)
	if e != nil { return Document{}, objectstore.SignedRequest{}, e }
	defer tx.Rollback(ctx)
	var out Document
	e = tx.QueryRow(ctx, `INSERT INTO documents(public_id,tenant_id,environment,party_id,owner_type,owner_id,source_application,source_reference,consent_reference,document_type,purpose,classification,original_filename,content_type,size_bytes,sha256_hex,bucket_name,object_key,retention_category,retain_until,upload_expires_at,created_by,idempotency_key,request_hash) VALUES($1,$2,$3,NULLIF($4,''),$5,$6,$7,NULLIF($8,''),NULLIF($9,''),$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24) RETURNING public_id,COALESCE(party_id,''),owner_type,owner_id,status,scan_status,document_type,purpose,classification,content_type,size_bytes,sha256_hex,created_at`, id, scope.TenantID, scope.Environment, in.PartyID, in.OwnerType, in.OwnerID, scope.ApplicationID, in.SourceReference, in.ConsentReference, in.DocumentType, in.Purpose, in.Classification, in.Filename, in.ContentType, in.Size, in.SHA256, s.bucket, key, in.RetentionCategory, in.RetainUntil, expires, scope.Subject, in.IdempotencyKey, requestHash).Scan(&out.ID, &out.PartyID, &out.OwnerType, &out.OwnerID, &out.Status, &out.ScanStatus, &out.DocumentType, &out.Purpose, &out.Classification, &out.ContentType, &out.Size, &out.SHA256, &out.CreatedAt)
	if e != nil {
		return Document{}, objectstore.SignedRequest{}, e
	}
	out.objectKey, out.filename = key, in.Filename
	_, e = tx.Exec(ctx, `INSERT INTO document_audit_events(document_id,action,actor_subject,actor_application,correlation_id) SELECT id,'upload_authorized',$2,$3,$4 FROM documents WHERE public_id=$1`, id, scope.Subject, scope.ApplicationID, scope.CorrelationID)
	if e != nil {
		return Document{}, objectstore.SignedRequest{}, e
	}
	if e = tx.Commit(ctx); e != nil { return Document{}, objectstore.SignedRequest{}, e }
	signed, e := s.objects.PresignUpload(ctx, key, in.ContentType, in.SHA256, in.Size, s.uploadTTL)
	return out, signed, e
}
func (s *Service) getIdempotent(ctx context.Context, scope Scope, key, hash string) (Document, error) {
	var out Document
	var storedHash string
	e := s.db.QueryRow(ctx, `SELECT public_id,COALESCE(party_id,''),owner_type,owner_id,status,scan_status,document_type,purpose,classification,content_type,size_bytes,sha256_hex,created_at,object_key,original_filename,request_hash FROM documents WHERE tenant_id=$1 AND environment=$2 AND source_application=$3 AND idempotency_key=$4`, scope.TenantID, scope.Environment, scope.ApplicationID, key).Scan(&out.ID,&out.PartyID,&out.OwnerType,&out.OwnerID,&out.Status,&out.ScanStatus,&out.DocumentType,&out.Purpose,&out.Classification,&out.ContentType,&out.Size,&out.SHA256,&out.CreatedAt,&out.objectKey,&out.filename,&storedHash)
	if errors.Is(e, pgx.ErrNoRows) { return Document{}, ErrNotFound }
	if e != nil { return Document{}, e }
	if storedHash != hash { return Document{}, ErrConflict }
	return out, nil
}
func (s *Service) Complete(ctx context.Context, scope Scope, id string) (Document, error) {
	out, e := s.get(ctx, scope, id)
	if e != nil {
		return Document{}, e
	}
	if out.Status != "pending_upload" {
		return Document{}, ErrConflict
	}
	if e = s.objects.Verify(ctx, out.objectKey, out.SHA256, out.Size); e != nil {
		return Document{}, ErrConflict
	}
	e = s.db.QueryRow(ctx, `UPDATE documents SET status='quarantined',uploaded_at=now(),updated_at=now() WHERE public_id=$1 AND tenant_id=$2 AND environment=$3 AND status='pending_upload' RETURNING public_id,COALESCE(party_id,''),owner_type,owner_id,status,scan_status,document_type,purpose,classification,content_type,size_bytes,sha256_hex,created_at`, id, scope.TenantID, scope.Environment).Scan(&out.ID, &out.PartyID, &out.OwnerType, &out.OwnerID, &out.Status, &out.ScanStatus, &out.DocumentType, &out.Purpose, &out.Classification, &out.ContentType, &out.Size, &out.SHA256, &out.CreatedAt)
	if e != nil {
		return Document{}, e
	}
	_, e = s.db.Exec(ctx, `INSERT INTO document_audit_events(document_id,action,actor_subject,actor_application,correlation_id) SELECT id,'upload_verified_quarantined',$2,$3,$4 FROM documents WHERE public_id=$1`, id, scope.Subject, scope.ApplicationID, scope.CorrelationID)
	return out, e
}
func (s *Service) RecordScan(ctx context.Context, scope Scope, id, outcome, reason string) (Document, error) {
	if outcome != "clean" && outcome != "infected" && outcome != "failed" {
		return Document{}, ErrConflict
	}
	status := "quarantined"
	if outcome == "clean" {
		status = "available"
	} else if outcome == "infected" {
		status = "rejected"
	}
	var out Document
	e := s.db.QueryRow(ctx, `UPDATE documents SET scan_status=$4,status=$5,updated_at=now() WHERE public_id=$1 AND tenant_id=$2 AND environment=$3 AND status='quarantined' AND scan_status='pending' RETURNING public_id,COALESCE(party_id,''),owner_type,owner_id,status,scan_status,document_type,purpose,classification,content_type,size_bytes,sha256_hex,created_at`, id, scope.TenantID, scope.Environment, outcome, status).Scan(&out.ID, &out.PartyID, &out.OwnerType, &out.OwnerID, &out.Status, &out.ScanStatus, &out.DocumentType, &out.Purpose, &out.Classification, &out.ContentType, &out.Size, &out.SHA256, &out.CreatedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return Document{}, ErrConflict
	}
	if e != nil {
		return Document{}, e
	}
	_, e = s.db.Exec(ctx, `INSERT INTO document_audit_events(document_id,action,actor_subject,actor_application,correlation_id,reason) SELECT id,'malware_scan_'||$2,$3,$4,$5,$6 FROM documents WHERE public_id=$1`, id, outcome, scope.Subject, scope.ApplicationID, scope.CorrelationID, reason)
	return out, e
}
func (s *Service) Download(ctx context.Context, scope Scope, id string) (objectstore.SignedRequest, error) {
	out, e := s.get(ctx, scope, id)
	if e != nil {
		return objectstore.SignedRequest{}, e
	}
	if out.Status != "available" || out.ScanStatus != "clean" {
		return objectstore.SignedRequest{}, ErrConflict
	}
	signed, e := s.objects.PresignDownload(ctx, out.objectKey, out.filename, s.downloadTTL)
	if e != nil {
		return signed, e
	}
	_, e = s.db.Exec(ctx, `INSERT INTO document_audit_events(document_id,action,actor_subject,actor_application,correlation_id) SELECT id,'download_authorized',$2,$3,$4 FROM documents WHERE public_id=$1`, id, scope.Subject, scope.ApplicationID, scope.CorrelationID)
	return signed, e
}
func (s *Service) get(ctx context.Context, scope Scope, id string) (Document, error) {
	var out Document
	e := s.db.QueryRow(ctx, `SELECT public_id,COALESCE(party_id,''),owner_type,owner_id,status,scan_status,document_type,purpose,classification,content_type,size_bytes,sha256_hex,created_at,object_key,original_filename FROM documents WHERE public_id=$1 AND tenant_id=$2 AND environment=$3`, id, scope.TenantID, scope.Environment).Scan(&out.ID, &out.PartyID, &out.OwnerType, &out.OwnerID, &out.Status, &out.ScanStatus, &out.DocumentType, &out.Purpose, &out.Classification, &out.ContentType, &out.Size, &out.SHA256, &out.CreatedAt, &out.objectKey, &out.filename)
	if errors.Is(e, pgx.ErrNoRows) {
		return Document{}, ErrNotFound
	}
	return out, e
}
func newID(prefix string) string {
	var b [16]byte
	if _, e := rand.Read(b[:]); e != nil {
		panic(e)
	}
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b[:]))
}
