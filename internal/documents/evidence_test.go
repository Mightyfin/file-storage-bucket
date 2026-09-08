package documents

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"strings"
	"testing"
)

func TestEvidenceRejectsMissingScopeBeforeLookup(t *testing.T) {
	s := &Service{}
	for _, sc := range []Scope{{}, {TenantID: "t"}, {TenantID: "t", Environment: "sandbox", Subject: "a"}} {
		if _, err := s.Evidence(context.Background(), sc, "doc", "party", strings.Repeat("a", 64)); !errors.Is(err, ErrEvidenceScope) {
			t.Fatal(err)
		}
	}
}

func TestEvidenceIsolationAndAudit(t *testing.T) {
	dsn := os.Getenv("DOCUMENT_EVIDENCE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("isolated test database required")
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
	_, err = db.Exec(ctx, `CREATE TEMP TABLE documents(id int,public_id text,tenant_id text,environment text,party_id text,owner_type text,owner_id text,status text,scan_status text,document_type text,purpose text,classification text,content_type text,size_bytes bigint,sha256_hex text,created_at timestamptz,source_reference text,object_key text,original_filename text);
 CREATE TEMP TABLE document_audit_events(document_id int,action text,actor_subject text,actor_application text,correlation_id text);
 INSERT INTO documents VALUES(1,'doc','tenant-a','sandbox','party-a','PARTY','party-a','available','clean','BANK_STATEMENT','credit','RESTRICTED','application/pdf',10,repeat('a',64),now(),'case-a','object-a','fixture.pdf');`)
	if err != nil {
		t.Fatal(err)
	}
	s := &Service{db: db}
	for _, tc := range []struct {
		tenant, env, party, application string
		allowed                         bool
	}{{"tenant-a", "sandbox", "party-a", "case-a", true}, {"tenant-b", "sandbox", "party-a", "case-a", false}, {"tenant-a", "production", "party-a", "case-a", false}, {"tenant-a", "sandbox", "party-b", "case-a", false}, {"tenant-a", "sandbox", "party-a", "case-b", false}} {
		sc := Scope{TenantID: tc.tenant, Environment: tc.env, Subject: "actor", ApplicationID: "console"}
		_, checkErr := s.CaseUpload(ctx, sc, tc.application, tc.party, "doc")
		if (checkErr == nil) != tc.allowed {
			t.Fatalf("case upload isolation: %+v %v", tc, checkErr)
		}
		items, checkErr := s.CaseUploads(ctx, sc, tc.application, tc.party, "")
		if checkErr != nil || (len(items) == 1) != tc.allowed {
			t.Fatalf("case list isolation: %+v %v", tc, checkErr)
		}
	}
	digest := strings.Repeat("a", 64)
	for _, tc := range []struct {
		name, tenant, env, party, hash string
		want                           error
	}{
		{"valid", "tenant-a", "sandbox", "party-a", digest, nil},
		{"foreign tenant", "tenant-b", "sandbox", "party-a", digest, ErrNotFound},
		{"foreign env", "tenant-a", "production", "party-a", digest, ErrNotFound},
		{"foreign party", "tenant-a", "sandbox", "party-b", digest, ErrNotFound},
		{"wrong version", "tenant-a", "sandbox", "party-a", strings.Repeat("b", 64), ErrConflict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, e := s.Evidence(ctx, Scope{TenantID: tc.tenant, Environment: tc.env, Subject: "actor", ApplicationID: "client"}, "doc", tc.party, tc.hash)
			if !errors.Is(e, tc.want) {
				t.Fatalf("got %v want %v", e, tc.want)
			}
		})
	}
	for _, scan := range []string{"pending", "infected", "failed"} {
		if _, err = db.Exec(ctx, `UPDATE documents SET scan_status=$1`, scan); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Evidence(ctx, Scope{TenantID: "tenant-a", Environment: "sandbox", Subject: "actor", ApplicationID: "client"}, "doc", "party-a", digest); !errors.Is(err, ErrConflict) {
			t.Fatal(err)
		}
	}
	var count int
	if err = db.QueryRow(ctx, `SELECT count(*) FROM document_audit_events WHERE actor_subject='actor' AND action='evidence_version_checked'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("audit count=%d error=%v", count, err)
	}
}
