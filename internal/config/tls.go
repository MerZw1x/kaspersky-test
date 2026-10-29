package config

import "errors"

type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

func (cfg TLSConfig) Enabled() bool { return cfg.CertFile != "" && cfg.KeyFile != "" }

func (cfg TLSConfig) validate() error {
	if (cfg.CertFile == "") != (cfg.KeyFile == "") {
		return errors.New("http_server.tls.cert_file and key_file must be set together")
	}

	return nil
}
