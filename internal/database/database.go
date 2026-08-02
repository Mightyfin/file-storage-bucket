package database

import (
	"context"
	"embed"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

func Open(ctx context.Context, url string) (*pgxpool.Pool, error) { return pgxpool.New(ctx, url) }
func Migrate(ctx context.Context, url string) error {
	pool, err := Open(ctx, url)
	if err != nil {
		return err
	}
	defer pool.Close()
	db, err := goose.OpenDBWithDriver("pgx", url)
	if err != nil {
		return err
	}
	defer db.Close()
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		return err
	}
	goose.SetBaseFS(sub)
	if err = goose.UpContext(ctx, db, "."); err != nil {
		return fmt.Errorf("migrate documents: %w", err)
	}
	return nil
}
