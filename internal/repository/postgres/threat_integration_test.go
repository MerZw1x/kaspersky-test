package postgres_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	migratedb "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"backend/db/migration"
	"backend/internal/config"
	"backend/internal/domain"
	errs "backend/internal/errors"
	"backend/internal/repository/postgres"
	"backend/internal/service"
)

func setupDB(t *testing.T) (*sqlx.DB, config.DatabaseConfig) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	container, err := tcpostgres.Run(ctx, "postgres:17-alpine",
		tcpostgres.WithDatabase("threatintel"), tcpostgres.WithUsername("test"), tcpostgres.WithPassword("test"),
		tcpostgres.BasicWaitStrategies())
	if container != nil {
		testcontainers.CleanupContainer(t, container)
	}
	require.NoError(t, err)
	dsn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)
	cfg, err := config.ReadConfig()
	require.NoError(t, err)
	cfg.Database.DSN = dsn
	db, err := postgres.Open(ctx, cfg.Database)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	require.NoError(t, postgres.Migrate(ctx, db, cfg.Database.MigrationTimeout))
	return db, cfg.Database
}

func record(id int) domain.Threat {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	return domain.Threat{
		MD5: fmt.Sprintf("%032x", id), Name: "Trojan.Win32.Generic", Type: domain.ThreatTypeTrojan,
		Platform: domain.PlatformWindows, Severity: domain.SeverityHigh, Status: domain.ThreatStatusActive,
		Tags: []string{}, CreatedAt: now, UpdatedAt: now,
	}
}

func pointer[T any](value T) *T { return &value }

func TestPostgres(t *testing.T) {
	db, cfg := setupDB(t)
	repo := postgres.NewThreatRepository(db)
	ctx := context.Background()

	t.Run("repeated migration keeps pool open", func(t *testing.T) {
		require.NoError(t, postgres.Migrate(ctx, db, cfg.MigrationTimeout))
		require.NoError(t, db.PingContext(ctx))
	})

	t.Run("migration lock waits are bounded", func(t *testing.T) {
		tx, err := db.BeginTxx(ctx, nil)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback() }()
		_, err = tx.ExecContext(ctx, "LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE")
		require.NoError(t, err)
		started := time.Now()
		err = postgres.Migrate(ctx, db, 50*time.Millisecond)
		require.Error(t, err)
		require.Less(t, time.Since(started), 2*time.Second)
		require.NoError(t, tx.Rollback())
		require.NoError(t, postgres.Migrate(ctx, db, cfg.MigrationTimeout))
	})

	t.Run("minimal record round trip", func(t *testing.T) {
		want := record(1)
		got, err := repo.Create(ctx, want)
		require.NoError(t, err)
		require.Equal(t, want, got)
		got, err = repo.GetByMD5(ctx, want.MD5)
		require.NoError(t, err)
		require.Equal(t, want, got)
		require.NotNil(t, got.Tags)
	})

	t.Run("all nullable fields and special tags round trip", func(t *testing.T) {
		want := record(2)
		want.SHA256 = pointer(strings.Repeat("a", 64))
		want.FileSize = pointer(int64(0))
		want.Description = pointer("Описание угрозы")
		want.Tags = []string{"apt", "comma,quote\"", "back\\slash"}
		want.FirstSeen = pointer(want.CreatedAt.Add(-time.Hour))
		want.LastSeen = pointer(want.CreatedAt)
		got, err := repo.Create(ctx, want)
		require.NoError(t, err)
		require.Equal(t, want, got)
		got, err = repo.GetByMD5(ctx, want.MD5)
		require.NoError(t, err)
		require.Equal(t, want, got)
	})

	t.Run("duplicate maps to domain error", func(t *testing.T) {
		_, err := repo.Create(ctx, record(1))
		require.ErrorIs(t, err, errs.ErrAlreadyExists)
	})

	t.Run("missing get and update", func(t *testing.T) {
		_, err := repo.GetByMD5(ctx, record(99).MD5)
		require.ErrorIs(t, err, errs.ErrNotFound)
		_, err = repo.Update(ctx, record(99))
		require.ErrorIs(t, err, errs.ErrNotFound)
	})

	t.Run("full replacement clears fields and preserves creation time", func(t *testing.T) {
		old, err := repo.GetByMD5(ctx, record(2).MD5)
		require.NoError(t, err)
		replacement := record(2)
		replacement.Name = "Backdoor.AndroidOS.Triada.a"
		replacement.Type = domain.ThreatTypeBackdoor
		replacement.Platform = domain.PlatformAndroid
		replacement.CreatedAt = time.Time{}
		replacement.UpdatedAt = old.UpdatedAt.Add(time.Hour)
		replacement.Tags = nil
		got, err := repo.Update(ctx, replacement)
		require.NoError(t, err)
		replacement.CreatedAt = old.CreatedAt
		replacement.Tags = []string{}
		require.Equal(t, replacement, got)
		stored, err := repo.GetByMD5(ctx, replacement.MD5)
		require.NoError(t, err)
		require.Equal(t, got, stored)
	})

	t.Run("concurrent duplicate creates exactly one record", func(t *testing.T) {
		const workers = 12
		failures := make(chan error, workers)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for range workers {
			wg.Go(func() {
				<-start
				_, err := repo.Create(ctx, record(3))
				failures <- err
			})
		}
		close(start)
		wg.Wait()
		close(failures)
		successes, duplicates := 0, 0
		for err := range failures {
			if err == nil {
				successes++
			} else {
				require.ErrorIs(t, err, errs.ErrAlreadyExists)
				duplicates++
			}
		}
		require.Equal(t, 1, successes)
		require.Equal(t, workers-1, duplicates)
		var count int
		require.NoError(t, db.GetContext(ctx, &count, "SELECT count(*) FROM threats WHERE md5=$1", record(3).MD5))
		require.Equal(t, 1, count)
	})

	t.Run("check violations remain database errors", func(t *testing.T) {
		invalid := record(4)
		invalid.FileSize = pointer(int64(-1))
		_, err := repo.Create(ctx, invalid)
		require.Error(t, err)
		require.NotErrorIs(t, err, errs.ErrAlreadyExists)
		require.NotErrorIs(t, err, errs.ErrNotFound)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "23514", pgErr.Code)
	})

	t.Run("canceled queries preserve context error", func(t *testing.T) {
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		_, err := repo.GetByMD5(canceled, record(1).MD5)
		require.ErrorIs(t, err, context.Canceled)
		_, err = repo.Create(canceled, record(5))
		require.ErrorIs(t, err, context.Canceled)
		_, err = repo.Update(canceled, record(1))
		require.ErrorIs(t, err, context.Canceled)
	})

	t.Run("service and repository normalize duplicate hash", func(t *testing.T) {
		now := record(6).CreatedAt
		svc := service.NewThreatService(repo, func() time.Time { return now })
		key := "abcdefabcdefabcdefabcdefabcdefab"
		input := domain.ThreatInput{Name: "Trojan.Win32.Generic"}
		created, err := svc.Create(ctx, strings.ToUpper(key), input)
		require.NoError(t, err)
		require.Equal(t, key, created.MD5)
		_, err = svc.Create(ctx, key, input)
		require.ErrorIs(t, err, errs.ErrAlreadyExists)
		input.Name = "Backdoor.AndroidOS.Triada.a"
		updated, err := svc.Update(ctx, strings.ToUpper(key), input)
		require.NoError(t, err)
		require.Equal(t, created.CreatedAt, updated.CreatedAt)
		require.Equal(t, input.Name, updated.Name)
	})

	t.Run("closed connection is not not-found", func(t *testing.T) {
		separate, err := postgres.Open(ctx, cfg)
		require.NoError(t, err)
		require.NoError(t, separate.Close())
		_, err = postgres.NewThreatRepository(separate).GetByMD5(ctx, record(1).MD5)
		require.Error(t, err)
		require.False(t, errors.Is(err, errs.ErrNotFound))
	})

	t.Run("migration down and up", func(t *testing.T) {
		source, err := iofs.New(migration.Files, ".")
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, source.Close()) })
		conn, err := db.Conn(ctx)
		require.NoError(t, err)
		driver, err := migratedb.WithConnection(ctx, conn, &migratedb.Config{StatementTimeout: cfg.MigrationTimeout})
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, driver.Close()) })
		runner, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
		require.NoError(t, err)
		require.NoError(t, runner.Down())
		var exists bool
		require.NoError(t, db.GetContext(ctx, &exists, "SELECT to_regclass('public.threats') IS NOT NULL"))
		require.False(t, exists)
		require.NoError(t, runner.Up())
		_, err = repo.Create(ctx, record(7))
		require.NoError(t, err)
	})
}
