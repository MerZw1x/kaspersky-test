package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"backend/internal/config"
)

func TestDatabaseConfig(t *testing.T) {
	t.Setenv("TEST_DATABASE_URL", "postgres://user:password@db:5432/custom?sslmode=require")
	cfg, err := config.ReadConfig(writeConfig(t, `database:
  dsn: ${TEST_DATABASE_URL}
  max_open_conns: 20
  max_idle_conns: 0
  conn_max_lifetime: 1h
  connect_timeout: 2s
  migration_timeout: 15s
`))
	require.NoError(t, err)
	require.Equal(t, "postgres://user:password@db:5432/custom?sslmode=require", cfg.Database.DSN)
	require.Equal(t, 20, cfg.Database.MaxOpenConns)
	require.Zero(t, cfg.Database.MaxIdleConns)
	require.Equal(t, time.Hour, cfg.Database.ConnMaxLifetime)
	require.Equal(t, 2*time.Second, cfg.Database.ConnectTimeout)
	require.Equal(t, 15*time.Second, cfg.Database.MigrationTimeout)
}

func TestDatabaseConfigInvalid(t *testing.T) {
	for _, tt := range []struct{ name, body, field string }{
		{"empty dsn", `dsn: ""`, "dsn"},
		{"no open connections", "max_open_conns: 0", "max_open_conns"},
		{"negative idle connections", "max_idle_conns: -1", "max_idle_conns"},
		{"idle exceeds open", "max_idle_conns: 11", "max_idle_conns"},
		{"zero lifetime", "conn_max_lifetime: 0s", "conn_max_lifetime"},
		{"zero connect timeout", "connect_timeout: 0s", "connect_timeout"},
		{"negative migration timeout", "migration_timeout: -1s", "migration_timeout"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.ReadConfig(writeConfig(t, "database:\n  "+tt.body+"\n"))
			require.Error(t, err)
			require.Nil(t, cfg)
			require.Contains(t, err.Error(), "database."+tt.field)
		})
	}
}
