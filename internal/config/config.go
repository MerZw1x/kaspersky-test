package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"
)

// Допустимые значения log.format.
const (
	LogFormatJSON    = "json"
	LogFormatConsole = "console"
)

// Значения по умолчанию — безопасные для прода: если ключ забыли указать
// в YAML, сервис всё равно стартует с таймаутами и без debug-логов.
const (
	defaultLogLevel          = "info"
	defaultListen            = ":8000"
	defaultReadHeaderTimeout = 5 * time.Second
	defaultReadTimeout       = 10 * time.Second
	defaultWriteTimeout      = 10 * time.Second
	defaultIdleTimeout       = 60 * time.Second
	defaultGracefulTimeout   = 10 * time.Second
)

type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type HTTPServerConfig struct {
	Listen            string        `yaml:"listen"`
	ReadTimeout       time.Duration `yaml:"read_timeout"`
	WriteTimeout      time.Duration `yaml:"write_timeout"`
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
}

type Config struct {
	Log             LogConfig        `yaml:"log"`
	HTTPServer      HTTPServerConfig `yaml:"http_server"`
	GracefulTimeout time.Duration    `yaml:"graceful_timeout"`
}

func ReadConfig(paths ...string) (*Config, error) {
	config := defaultConfig()

	for _, path := range paths {
		yamlFile, err := os.ReadFile(path) //nolint:gosec // путь из CLI-флага --config
		if err != nil {
			return nil, fmt.Errorf("read file %s: %w", path, err)
		}

		expandedData := os.ExpandEnv(string(yamlFile)) // resolve envs, e.g. field: ${ENV_NAME}

		err = yaml.Unmarshal([]byte(expandedData), &config)
		if err != nil {
			return nil, fmt.Errorf("parse file %s: %w", path, err)
		}
	}

	if err := config.validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

func (cfg Config) validate() error {
	var errs []error

	if cfg.GracefulTimeout <= 0 {
		errs = append(errs, errors.New("graceful_timeout must be > 0"))
	}

	if cfg.HTTPServer.ReadHeaderTimeout <= 0 {
		errs = append(errs, errors.New("http_server.read_header_timeout must be > 0"))
	}

	if cfg.HTTPServer.ReadTimeout <= 0 {
		errs = append(errs, errors.New("http_server.read_timeout must be > 0"))
	}

	if cfg.HTTPServer.WriteTimeout <= 0 {
		errs = append(errs, errors.New("http_server.write_timeout must be > 0"))
	}

	if cfg.HTTPServer.IdleTimeout <= 0 {
		errs = append(errs, errors.New("http_server.idle_timeout must be > 0"))
	}

	if cfg.HTTPServer.Listen == "" {
		errs = append(errs, errors.New("http_server.listen must not be empty"))
	}

	if _, err := zapcore.ParseLevel(cfg.Log.Level); err != nil {
		errs = append(errs, fmt.Errorf("invalid log level: %w", err))
	}

	if cfg.Log.Format != LogFormatJSON && cfg.Log.Format != LogFormatConsole {
		errs = append(errs, errors.New("log format must be json or console"))
	}

	return errors.Join(errs...)
}

func defaultConfig() Config {
	return Config{
		Log: LogConfig{
			Level:  defaultLogLevel,
			Format: LogFormatJSON,
		},
		HTTPServer: HTTPServerConfig{
			Listen:            defaultListen,
			ReadHeaderTimeout: defaultReadHeaderTimeout,
			ReadTimeout:       defaultReadTimeout,
			WriteTimeout:      defaultWriteTimeout,
			IdleTimeout:       defaultIdleTimeout,
		},
		GracefulTimeout: defaultGracefulTimeout,
	}
}
