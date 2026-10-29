package app

import (
	"crypto/tls"
	"fmt"

	"backend/internal/config"
)

func serverTLSConfig(cfg config.TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled() {
		return nil, nil
	}

	certificate, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS certificate: %w", err)
	}

	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}}, nil
}
