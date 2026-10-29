package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"backend/internal/config"
)

func TestAPIKeysReadDirectlyFromEnvironment(t *testing.T) {
	reader := "reader $ ' \" \\ " + strings.Repeat("a", 16)
	writer := "writer $ ' \" \\ " + strings.Repeat("b", 16)
	t.Setenv("READER_API_KEY", reader)
	t.Setenv("WRITER_API_KEY", writer)
	cfg, err := config.ReadConfig(writeConfig(t, "security:\n  auth:\n    enabled: true\n"))
	require.NoError(t, err)
	require.Equal(t, reader, cfg.Security.Auth.ReaderKey)
	require.Equal(t, writer, cfg.Security.Auth.WriterKey)
}

func TestAuthConfigValidation(t *testing.T) {
	for _, tt := range []struct {
		name, reader, writer string
		valid                bool
	}{
		{name: "valid", reader: strings.Repeat("a", 16), writer: strings.Repeat("b", 16), valid: true},
		{name: "missing keys"},
		{name: "short reader", reader: "short", writer: strings.Repeat("b", 16)},
		{name: "short writer", reader: strings.Repeat("a", 16), writer: "short"},
		{name: "identical", reader: strings.Repeat("a", 16), writer: strings.Repeat("a", 16)},
		{name: "oversized", reader: strings.Repeat("a", 257), writer: strings.Repeat("b", 16)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.SecurityConfig{Auth: config.AuthConfig{Enabled: true, ReaderKey: tt.reader, WriterKey: tt.writer}}
			err := cfg.Validate()
			if tt.valid {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
				if len(tt.reader) >= 16 {
					require.NotContains(t, err.Error(), tt.reader)
				}
			}
		})
	}
}

func TestRateLimitConfigValidation(t *testing.T) {
	for _, field := range []string{"requests_per_second", "burst", "max_clients", "idle_ttl"} {
		t.Run(field, func(t *testing.T) {
			cfg := config.RateLimitConfig{Enabled: true, RequestsPerSecond: 10, Burst: 20, MaxClients: 100, IdleTTL: time.Minute}
			switch field {
			case "requests_per_second":
				cfg.RequestsPerSecond = 0
			case "burst":
				cfg.Burst = -1
			case "max_clients":
				cfg.MaxClients = 0
			case "idle_ttl":
				cfg.IdleTTL = 0
			}
			err := (config.SecurityConfig{RateLimit: cfg}).Validate()
			require.Error(t, err)
			require.Contains(t, err.Error(), field)
		})
	}
}

func TestTLSConfigRequiresPair(t *testing.T) {
	for _, body := range []string{"cert_file: certificate.pem", "key_file: private.pem"} {
		_, err := config.ReadConfig(writeConfig(t, "http_server:\n  tls:\n    "+body+"\n"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "must be set together")
	}
	cfg, err := config.ReadConfig(writeConfig(t, "http_server:\n  tls:\n    cert_file: certificate.pem\n    key_file: private.pem\n"))
	require.NoError(t, err)
	require.True(t, cfg.HTTPServer.TLS.Enabled())
}
