package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Mightyfin/file-storage-bucket/internal/config"
	"github.com/Mightyfin/file-storage-bucket/internal/database"
	"github.com/Mightyfin/file-storage-bucket/internal/documents"
	"github.com/Mightyfin/file-storage-bucket/internal/malware"
	"github.com/Mightyfin/file-storage-bucket/internal/objectstore"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout,nil))
	c, err := config.Load(); if err != nil { log.Error("configuration rejected","error",err); os.Exit(1) }
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM); defer stop()
	db, err := database.Open(ctx,c.DatabaseURL); if err != nil { log.Error("database unavailable","error",err); os.Exit(1) }; defer db.Close()
	objects := objectstore.New(c.S3Endpoint,c.S3Region,c.S3AccessKey,c.S3SecretKey,c.S3Bucket)
	scanner := malware.Clamd{Address:c.ClamAddress,Timeout:2*time.Minute}
	ticker := time.NewTicker(c.ScanInterval); defer ticker.Stop()
	for {
		if err := processOne(ctx,db,objects,scanner,log); err != nil { log.Error("scan cycle failed","error",err) }
		select { case <-ctx.Done(): return; case <-ticker.C: }
	}
}

type opener interface { Open(context.Context,string)(io.ReadCloser,error) }
type virusScanner interface { Scan(context.Context,io.Reader)(string,string,error) }

func processOne(ctx context.Context, db *pgxpool.Pool, objects opener, scanner virusScanner, log *slog.Logger) error {
	var id,tenant,environment,key string
	err := db.QueryRow(ctx, `WITH candidate AS (
		SELECT id FROM documents WHERE status='quarantined'
		AND (scan_status IN ('pending','failed') OR (scan_status='scanning' AND scan_lease_until<now()))
		AND scan_attempts<5 ORDER BY uploaded_at FOR UPDATE SKIP LOCKED LIMIT 1
	) UPDATE documents d SET scan_status='scanning',scan_attempts=scan_attempts+1,
		scan_lease_until=now()+interval '3 minutes',updated_at=now()
		FROM candidate c WHERE d.id=c.id
		RETURNING d.public_id,d.tenant_id,d.environment,d.object_key`).Scan(&id,&tenant,&environment,&key)
	if errors.Is(err,pgx.ErrNoRows) { return nil }; if err != nil { return err }
	body, err := objects.Open(ctx,key); if err != nil { return err }; defer body.Close()
	outcome, reason, scanErr := scanner.Scan(ctx,body)
	service := documents.New(db,nil,nil,"",0,0)
	_, recordErr := service.RecordScan(ctx,documents.Scope{TenantID:tenant,Environment:environment,Subject:"document-scanner",ApplicationID:"file-storage-scanner",CorrelationID:"scan-"+id},id,outcome,reason)
	if recordErr != nil { return recordErr }
	log.Info("document scanned","document_id",id,"outcome",outcome)
	return scanErr
}
