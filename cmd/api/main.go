package main

import (
	"context"
	"errors"
	"github.com/Mightyfin/document-service/internal/auth"
	"github.com/Mightyfin/document-service/internal/config"
	"github.com/Mightyfin/document-service/internal/database"
	"github.com/Mightyfin/document-service/internal/documents"
	"github.com/Mightyfin/document-service/internal/httpserver"
	"github.com/Mightyfin/document-service/internal/objectstore"
	"github.com/Mightyfin/document-service/internal/party"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	l := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	c, e := config.Load()
	if e != nil {
		l.Error("configuration rejected", "error", e)
		os.Exit(1)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	db, e := database.Open(ctx, c.DatabaseURL)
	if e != nil {
		l.Error("database unavailable", "error", e)
		os.Exit(1)
	}
	defer db.Close()
	objects := objectstore.New(c.S3Endpoint, c.S3Region, c.S3AccessKey, c.S3SecretKey, c.S3Bucket)
	if e = objects.EnsureBucket(ctx); e != nil {
		l.Error("object storage unavailable", "error", e)
		os.Exit(1)
	}
	parties, e := party.New(ctx, c.PartyBaseURL, c.PartyTokenURL, c.PartyClientID, c.PartyClientSecret, c.AuthMode == "disabled")
	if e != nil {
		l.Error("Party Platform unavailable", "error", e)
		os.Exit(1)
	}
	var verifier auth.Verifier
	if c.AuthMode == "oidc" {
		verifier, e = auth.New(ctx, c.OIDCIssuer, c.OIDCAudience, c.Environment)
		if e != nil {
			l.Error("OIDC unavailable", "error", e)
			os.Exit(1)
		}
	}
	server := httpserver.New(c, l, db, documents.New(db, parties, objects, c.S3Bucket, c.UploadTTL, c.DownloadTTL), verifier)
	go func() {
		if e := server.ListenAndServe(); e != nil && !errors.Is(e, http.ErrServerClosed) {
			l.Error("server stopped", "error", e)
			os.Exit(1)
		}
	}()
	<-ctx.Done()
	shutdown, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	_ = server.Shutdown(shutdown)
}
