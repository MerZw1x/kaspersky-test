package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"backend/internal/config"
)

const validYAML = `
log:
  level: debug
  format: console
http_server:
  listen: :9090
  read_header_timeout: 1s
  read_timeout: 2s
  write_timeout: 3s
  idle_timeout: 4s
graceful_timeout: 5s
`

// writeConfig кладёт YAML во временный файл и возвращает путь к нему.
func writeConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

func TestReadConfig_Valid(t *testing.T) {
	cfg, err := config.ReadConfig(writeConfig(t, validYAML))
	require.NoError(t, err)

	assert.Equal(t, &config.Config{
		Security: config.SecurityConfig{RateLimit: config.RateLimitConfig{
			Enabled: true, RequestsPerSecond: 10, Burst: 20, MaxClients: 10000, IdleTTL: 10 * time.Minute,
		}},
		Database: config.DatabaseConfig{
			DSN:          "postgres://threatintel:threatintel@localhost:5432/threatintel?sslmode=disable",
			MaxOpenConns: 10, MaxIdleConns: 5, ConnMaxLifetime: 30 * time.Minute,
			ConnectTimeout: 10 * time.Second, MigrationTimeout: 30 * time.Second,
		},
		Log: config.LogConfig{Level: "debug", Format: "console"},
		HTTPServer: config.HTTPServerConfig{
			Listen:            ":9090",
			ReadHeaderTimeout: 1 * time.Second,
			ReadTimeout:       2 * time.Second,
			WriteTimeout:      3 * time.Second,
			IdleTimeout:       4 * time.Second,
		},
		GracefulTimeout: 5 * time.Second,
	}, cfg)
}

func TestReadConfig_Defaults(t *testing.T) {
	tests := []struct {
		name    string
		content string
		check   func(t *testing.T, cfg *config.Config)
	}{
		{
			name:    "empty file gives production-safe defaults",
			content: "",
			check: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				assert.Equal(t, "info", cfg.Log.Level)
				assert.Equal(t, "json", cfg.Log.Format)
				assert.Equal(t, ":8000", cfg.HTTPServer.Listen)
				assert.Equal(t, 5*time.Second, cfg.HTTPServer.ReadHeaderTimeout)
				assert.Equal(t, 10*time.Second, cfg.HTTPServer.ReadTimeout)
				assert.Equal(t, 10*time.Second, cfg.HTTPServer.WriteTimeout)
				assert.Equal(t, 60*time.Second, cfg.HTTPServer.IdleTimeout)
				assert.Equal(t, 10*time.Second, cfg.GracefulTimeout)
			},
		},
		{
			name:    "missing key keeps default, present keys override",
			content: "http_server:\n  read_timeout: 30s\n",
			check: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				assert.Equal(t, 30*time.Second, cfg.HTTPServer.ReadTimeout)
				assert.Equal(t, 5*time.Second, cfg.HTTPServer.ReadHeaderTimeout)
				assert.Equal(t, ":8000", cfg.HTTPServer.Listen)
			},
		},
		{
			// ExpandEnv подставляет "", в YAML получается `listen:` (null),
			// а null не перетирает поле — остаётся дефолт.
			name:    "unset env keeps default",
			content: "http_server:\n  listen: ${TEST_UNSET_LISTEN}\n",
			check: func(t *testing.T, cfg *config.Config) {
				t.Helper()
				assert.Equal(t, ":8000", cfg.HTTPServer.Listen)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.ReadConfig(writeConfig(t, tt.content))
			require.NoError(t, err)
			tt.check(t, cfg)
		})
	}
}

func TestReadConfig_EnvExpansion(t *testing.T) {
	t.Setenv("TEST_LOG_LEVEL", "warn")
	t.Setenv("TEST_LISTEN", ":7070")

	cfg, err := config.ReadConfig(writeConfig(t, `
log:
  level: ${TEST_LOG_LEVEL}
http_server:
  listen: ${TEST_LISTEN}
`))
	require.NoError(t, err)

	assert.Equal(t, "warn", cfg.Log.Level)
	assert.Equal(t, ":7070", cfg.HTTPServer.Listen)
}

func TestReadConfig_LaterFileOverrides(t *testing.T) {
	base := writeConfig(t, validYAML)
	override := writeConfig(t, "log:\n  level: error\n")

	cfg, err := config.ReadConfig(base, override)
	require.NoError(t, err)

	assert.Equal(t, "error", cfg.Log.Level)
	assert.Equal(t, "console", cfg.Log.Format, "keys absent in override come from base")
	assert.Equal(t, ":9090", cfg.HTTPServer.Listen)
}

func TestReadConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name     string
		content  string
		wantErrs []string // каждая подстрока должна быть в тексте ошибки
	}{
		{
			name:     "zero timeout",
			content:  "http_server:\n  read_timeout: 0s\n",
			wantErrs: []string{"read_timeout"},
		},
		{
			name:     "negative timeout",
			content:  "http_server:\n  read_header_timeout: -1s\n",
			wantErrs: []string{"read_header_timeout"},
		},
		{
			name:     "negative graceful timeout",
			content:  "graceful_timeout: -5s\n",
			wantErrs: []string{"graceful_timeout"},
		},
		{
			name:     "empty listen",
			content:  "http_server:\n  listen: \"\"\n",
			wantErrs: []string{"listen"},
		},
		{
			name:     "unknown log level",
			content:  "log:\n  level: verbose\n",
			wantErrs: []string{"log level"},
		},
		{
			name:     "unknown log format",
			content:  "log:\n  format: xml\n",
			wantErrs: []string{"log format"},
		},
		{
			name:     "all problems reported at once",
			content:  "http_server:\n  write_timeout: -1s\n  idle_timeout: 0s\nlog:\n  level: verbose\n",
			wantErrs: []string{"write_timeout", "idle_timeout", "log level"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.ReadConfig(writeConfig(t, tt.content))
			require.Error(t, err)
			assert.Nil(t, cfg)

			for _, want := range tt.wantErrs {
				assert.Contains(t, err.Error(), want)
			}
		})
	}
}

func TestReadConfig_FileErrors(t *testing.T) {
	t.Run("missing file error names the path", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "nope.yaml")

		_, err := config.ReadConfig(path)
		require.ErrorIs(t, err, os.ErrNotExist)
		assert.Contains(t, err.Error(), path)
	})

	t.Run("broken yaml error names the path", func(t *testing.T) {
		path := writeConfig(t, "log:\n\tlevel: debug\n") // таб в отступе — невалидный YAML

		_, err := config.ReadConfig(path)
		require.Error(t, err)
		assert.Contains(t, err.Error(), path)
	})

	t.Run("wrong type", func(t *testing.T) {
		_, err := config.ReadConfig(writeConfig(t, "http_server:\n  read_timeout: soon\n"))
		require.Error(t, err)
	})
}
