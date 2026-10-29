package config

import (
	"errors"
	"time"
)

const (
	//nolint:gosec // Тестовые реквизиты только для локального запуска.
	defaultDatabaseDSN      = "postgres://threatintel:threatintel@localhost:5432/threatintel?sslmode=disable"
	defaultMaxOpenConns     = 10
	defaultMaxIdleConns     = 5
	defaultConnMaxLifetime  = 30 * time.Minute
	defaultDatabaseTimeout  = 10 * time.Second
	defaultMigrationTimeout = 30 * time.Second
)

type DatabaseConfig struct {
	DSN              string        `yaml:"dsn"`
	MaxOpenConns     int           `yaml:"max_open_conns"`
	MaxIdleConns     int           `yaml:"max_idle_conns"`
	ConnMaxLifetime  time.Duration `yaml:"conn_max_lifetime"`
	ConnectTimeout   time.Duration `yaml:"connect_timeout"`
	MigrationTimeout time.Duration `yaml:"migration_timeout"`
}

func defaultDatabaseConfig() DatabaseConfig {
	return DatabaseConfig{
		DSN: defaultDatabaseDSN, MaxOpenConns: defaultMaxOpenConns, MaxIdleConns: defaultMaxIdleConns,
		ConnMaxLifetime: defaultConnMaxLifetime, ConnectTimeout: defaultDatabaseTimeout, MigrationTimeout: defaultMigrationTimeout,
	}
}

func (cfg DatabaseConfig) validate() error {
	var problems []error
	if cfg.DSN == "" {
		problems = append(problems, errors.New("database.dsn must not be empty"))
	}

	if cfg.MaxOpenConns <= 0 {
		problems = append(problems, errors.New("database.max_open_conns must be > 0"))
	}

	if cfg.MaxIdleConns < 0 || cfg.MaxIdleConns > cfg.MaxOpenConns {
		problems = append(problems, errors.New("database.max_idle_conns must be between 0 and max_open_conns"))
	}

	if cfg.ConnMaxLifetime <= 0 {
		problems = append(problems, errors.New("database.conn_max_lifetime must be > 0"))
	}

	if cfg.ConnectTimeout <= 0 {
		problems = append(problems, errors.New("database.connect_timeout must be > 0"))
	}

	if cfg.MigrationTimeout <= 0 {
		problems = append(problems, errors.New("database.migration_timeout must be > 0"))
	}

	return errors.Join(problems...)
}
