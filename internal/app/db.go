package app

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"

	"backend/internal/config"
	"backend/internal/repository/postgres"
)

func initDB(cfg config.DatabaseConfig) (*sqlx.DB, error) {
	db, err := postgres.Open(context.Background(), cfg)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.MigrationTimeout)
	defer cancel()

	if err := postgres.Migrate(ctx, db, cfg.MigrationTimeout); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialize schema: %w", err)
	}

	return db, nil
}
