package config

import (
	"fmt"
	"os"
	"time"

	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"
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
			return nil, err
		}

		expandedData := os.ExpandEnv(string(yamlFile)) // resolve envs, e.g. field: ${ENV_NAME}

		err = yaml.Unmarshal([]byte(expandedData), &config)
		if err != nil {
			return nil, err
		}
	}

	if err := config.validate(); err != nil {
		return nil, err
	}

	return &config, nil
}

func (cfg Config) validate() error {
	if cfg.GracefulTimeout == 0 {
		return fmt.Errorf("graceful_timeout must be > 0")
	}
	if cfg.HTTPServer.ReadHeaderTimeout == 0 {
		return fmt.Errorf("read_header_timeout must be > 0")
	}
	if cfg.HTTPServer.ReadTimeout == 0 {
		return fmt.Errorf("read_timeout must be > 0")
	}

	if cfg.HTTPServer.WriteTimeout == 0 {
		return fmt.Errorf("write_timeout must be > 0")
	}

	if cfg.HTTPServer.IdleTimeout == 0 {
		return fmt.Errorf("idle_timeout must be > 0")
	}

	if cfg.HTTPServer.Listen == "" {
		return fmt.Errorf("http server port must not be empty")
	}

	if _, err := zapcore.ParseLevel(cfg.Log.Level); err != nil {
		return fmt.Errorf("invalid log level: %w", err)
	}

	if cfg.Log.Format != "json" && cfg.Log.Format != "console" {
		return fmt.Errorf("log format must be json or console")
	}

	return nil
}

func defaultConfig() Config {
	return Config{
		Log: LogConfig{
			Level:  "debug",
			Format: "console",
		},
		HTTPServer: HTTPServerConfig{
			Listen:            ":8000",
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			IdleTimeout:       60 * time.Second,
			WriteTimeout:      10 * time.Second,
		},
		GracefulTimeout: 10 * time.Second,
	}
}
