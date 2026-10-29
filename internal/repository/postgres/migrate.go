package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratedb "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jmoiron/sqlx"

	"backend/db/migration"
)

func Migrate(ctx context.Context, db *sqlx.DB, timeout time.Duration) (resultErr error) {
	source, err := iofs.New(migration.Files, ".")
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}

	defer func() { resultErr = errors.Join(resultErr, source.Close()) }()

	// Драйвер миграций владеет отдельным соединением: его Close не должен закрывать рабочий пул.
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}

	restore, err := limitMigrationLocks(ctx, conn, timeout)
	if err != nil {
		_ = conn.Close()
		return err
	}

	defer func() { resultErr = errors.Join(resultErr, restore(), conn.Close()) }()

	driver, err := migratedb.WithConnection(ctx, conn, &migratedb.Config{StatementTimeout: timeout})
	if err != nil {
		return fmt.Errorf("create migration driver: %w", err)
	}

	runner, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}

	runner.LockTimeout = timeout
	if err := runner.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}

	return nil
}

func limitMigrationLocks(ctx context.Context, conn *sql.Conn, timeout time.Duration) (func() error, error) {
	var previous string
	if err := conn.QueryRowContext(ctx, "SHOW lock_timeout").Scan(&previous); err != nil {
		return nil, fmt.Errorf("read migration lock timeout: %w", err)
	}
	// При создании драйвера migrate тоже берёт блокировку, ещё до действия runner.LockTimeout.
	value := fmt.Sprintf("%dms", max(1, timeout.Milliseconds()))
	if _, err := conn.ExecContext(ctx, "SELECT set_config('lock_timeout', $1, false)", value); err != nil {
		return nil, fmt.Errorf("set migration lock timeout: %w", err)
	}

	return func() error {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		_, err := conn.ExecContext(cleanupCtx, "SELECT set_config('lock_timeout', $1, false)", previous)
		if err != nil {
			return fmt.Errorf("restore migration lock timeout: %w", err)
		}

		return nil
	}, nil
}
