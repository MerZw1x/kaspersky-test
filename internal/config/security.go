package config

import (
	"errors"
	"time"
)

const (
	defaultRequestsPerSecond = 10
	defaultBurst             = 20
	defaultMaxClients        = 10000
	defaultIdleTTL           = 10 * time.Minute
	minAPIKeyLength          = 16
	maxAPIKeyLength          = 256
)

type AuthConfig struct {
	Enabled   bool   `yaml:"enabled"`
	ReaderKey string `yaml:"-"`
	WriterKey string `yaml:"-"`
}

type RateLimitConfig struct {
	Enabled           bool          `yaml:"enabled"`
	RequestsPerSecond int           `yaml:"requests_per_second"`
	Burst             int           `yaml:"burst"`
	MaxClients        int           `yaml:"max_clients"`
	IdleTTL           time.Duration `yaml:"idle_ttl"`
}

type SecurityConfig struct {
	Auth      AuthConfig      `yaml:"auth"`
	RateLimit RateLimitConfig `yaml:"rate_limit"`
}

func defaultSecurityConfig() SecurityConfig {
	return SecurityConfig{RateLimit: RateLimitConfig{
		Enabled: true, RequestsPerSecond: defaultRequestsPerSecond, Burst: defaultBurst, MaxClients: defaultMaxClients, IdleTTL: defaultIdleTTL,
	}}
}

func (cfg SecurityConfig) Validate() error {
	var problems []error

	if cfg.Auth.Enabled {
		if len(cfg.Auth.ReaderKey) < minAPIKeyLength || len(cfg.Auth.ReaderKey) > maxAPIKeyLength {
			problems = append(problems, errors.New("READER_API_KEY must contain between 16 and 256 bytes"))
		}

		if len(cfg.Auth.WriterKey) < minAPIKeyLength || len(cfg.Auth.WriterKey) > maxAPIKeyLength {
			problems = append(problems, errors.New("WRITER_API_KEY must contain between 16 and 256 bytes"))
		}

		if cfg.Auth.ReaderKey == cfg.Auth.WriterKey {
			problems = append(problems, errors.New("reader and writer API keys must differ"))
		}
	}

	if cfg.RateLimit.Enabled {
		if cfg.RateLimit.RequestsPerSecond <= 0 {
			problems = append(problems, errors.New("security.rate_limit.requests_per_second must be > 0"))
		}

		if cfg.RateLimit.Burst <= 0 {
			problems = append(problems, errors.New("security.rate_limit.burst must be > 0"))
		}

		if cfg.RateLimit.MaxClients <= 0 {
			problems = append(problems, errors.New("security.rate_limit.max_clients must be > 0"))
		}

		if cfg.RateLimit.IdleTTL <= 0 {
			problems = append(problems, errors.New("security.rate_limit.idle_ttl must be > 0"))
		}
	}

	return errors.Join(problems...)
}
