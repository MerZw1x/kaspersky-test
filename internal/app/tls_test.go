package app

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"backend/internal/config"
)

func testCertificate(t *testing.T) config.TLSConfig {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	privateKey, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	directory := t.TempDir()
	cfg := config.TLSConfig{CertFile: filepath.Join(directory, "server.crt"), KeyFile: filepath.Join(directory, "server.key")}
	require.NoError(t, os.WriteFile(cfg.CertFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(cfg.KeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}), 0o600))
	return cfg
}

func TestServerTLS(t *testing.T) {
	cfg := testCertificate(t)
	tlsConfig, err := serverTLSConfig(cfg)
	require.NoError(t, err)
	require.Equal(t, uint16(tls.VersionTLS12), tlsConfig.MinVersion)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	server.TLS = tlsConfig
	server.StartTLS()
	defer server.Close()
	roots := x509.NewCertPool()
	certificate, err := os.ReadFile(cfg.CertFile)
	require.NoError(t, err)
	require.True(t, roots.AppendCertsFromPEM(certificate))
	transport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	response, err := client.Get(server.URL)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusNoContent, response.StatusCode)
	require.GreaterOrEqual(t, response.TLS.Version, uint16(tls.VersionTLS12))

	legacyTransport := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11, RootCAs: roots}}
	defer legacyTransport.CloseIdleConnections()
	legacy := &http.Client{Transport: legacyTransport, Timeout: time.Second}
	_, err = legacy.Get(server.URL)
	require.Error(t, err)
}

func TestServerTLSDisabledAndMissingCertificate(t *testing.T) {
	got, err := serverTLSConfig(config.TLSConfig{})
	require.NoError(t, err)
	require.Nil(t, got)
	_, err = serverTLSConfig(config.TLSConfig{CertFile: "missing.crt", KeyFile: "missing.key"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "load TLS certificate")
}
