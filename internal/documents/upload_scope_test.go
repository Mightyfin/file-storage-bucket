package documents

import (
	"context"
	"crypto/sha256"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"io"
	"os"
	"strings"
	"testing"
)

type uploadObjects struct {
	Objects
	puts int
}

func (o *uploadObjects) PutObject(_ context.Context, _, _, _ string, _ int64, r io.Reader) error {
	o.puts++
	_, err := io.ReadAll(r)
	return err
}
func (*uploadObjects) Verify(context.Context, string, string, int64) error { return nil }
func TestServiceUploadCompletesStoredTenantScope(t *testing.T) {
	dsn := os.Getenv("DOCUMENT_EVIDENCE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated database required")
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 1
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(ctx, `CREATE TEMP TABLE documents(id int,public_id text,tenant_id text,environment text,party_id text,owner_type text,owner_id text,status text,scan_status text,document_type text,purpose text,classification text,content_type text,size_bytes bigint,sha256_hex text,created_at timestamptz,object_key text,original_filename text,uploaded_at timestamptz,updated_at timestamptz);
 CREATE TEMP TABLE document_audit_events(document_id int,action text,actor_subject text,actor_application text,correlation_id text);`)
	if err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte("test")))
	_, err = db.Exec(ctx, `INSERT INTO documents VALUES(1,'doc','tenant-a','sandbox','party','PARTY','party','pending_upload','pending','CERTIFICATE','KYC_KYB','CONFIDENTIAL','text/plain',4,$1,now(),'object','file',null,now())`, hash)
	if err != nil {
		t.Fatal(err)
	}
	objects := &uploadObjects{}
	s := &Service{db: db, objects: objects}
	if _, err = s.UploadContent(ctx, Scope{TenantID: "tenant-b", Environment: "sandbox"}, "doc", strings.NewReader("test")); err != ErrNotFound {
		t.Fatal(err)
	}
	if objects.puts != 0 {
		t.Fatal("foreign tenant wrote bytes")
	}
	out, err := s.UploadContent(ctx, Scope{Subject: "service", ApplicationID: "document-party-client", CorrelationID: "test"}, "doc", strings.NewReader("test"))
	if err != nil || out.Status != "quarantined" {
		t.Fatal(out, err)
	}
	var count int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM document_audit_events WHERE action='upload_verified_quarantined' AND actor_subject='service'`).Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
}
