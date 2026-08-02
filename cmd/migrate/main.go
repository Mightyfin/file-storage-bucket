package main

import (
	"context"
	"github.com/Mightyfin/document-service/internal/config"
	"github.com/Mightyfin/document-service/internal/database"
	"log/slog"
	"os"
)

func main() {
	l := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	c, e := config.Load()
	if e != nil {
		l.Error("configuration rejected", "error", e)
		os.Exit(1)
	}
	if e = database.Migrate(context.Background(), c.DatabaseURL); e != nil {
		l.Error("migration failed", "error", e)
		os.Exit(1)
	}
	l.Info("document migrations complete")
}
