package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// generateTestCert creates a self-signed ECDSA P-256 certificate for "localhost"
// with 1 hour expiry and server auth extended key usage.
func generateTestCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	certPath = filepath.Join(dir, "server.crt")
	keyPath = filepath.Join(dir, "server.key")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, os.WriteFile(certPath, certPEM, 0o600))

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	require.NoError(t, os.WriteFile(keyPath, keyPEM, 0o600))

	return certPath, keyPath
}

// generateTestCA creates a self-signed CA certificate with cert sign and CRL sign key usage.
func generateTestCA(t *testing.T, dir string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	caPath := filepath.Join(dir, "ca.crt")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	require.NoError(t, os.WriteFile(caPath, caPEM, 0o600))

	return caPath
}

func TestBuildTLSConfig(t *testing.T) {
	t.Run("returns nil when no env vars set", func(t *testing.T) {
		cfg, err := buildTLSConfig("", "", "", "")
		require.NoError(t, err)
		assert.Nil(t, cfg)
	})

	t.Run("errors when only cert set", func(t *testing.T) {
		_, err := buildTLSConfig("/some/cert.pem", "", "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "both ORES_TLS_CERT and ORES_TLS_KEY must be set")
	})

	t.Run("errors when only key set", func(t *testing.T) {
		_, err := buildTLSConfig("", "/some/key.pem", "", "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "both ORES_TLS_CERT and ORES_TLS_KEY must be set")
	})

	t.Run("errors on unreadable cert file", func(t *testing.T) {
		_, err := buildTLSConfig("/nonexistent/cert.pem", "/nonexistent/key.pem", "", "")
		require.Error(t, err)
	})

	t.Run("builds TLS config with valid cert and key", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCert(t, dir)

		cfg, err := buildTLSConfig(certPath, keyPath, "", "")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
		assert.NotEmpty(t, cfg.CipherSuites)
		assert.Equal(t, tls.NoClientCert, cfg.ClientAuth)
	})

	t.Run("TLS 1.3 minimum version", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCert(t, dir)

		cfg, err := buildTLSConfig(certPath, keyPath, "", "1.3")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, uint16(tls.VersionTLS13), cfg.MinVersion)
	})

	t.Run("errors on invalid min version", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCert(t, dir)

		_, err := buildTLSConfig(certPath, keyPath, "", "1.1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported TLS minimum version")
	})

	t.Run("enables mTLS with client CA", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCert(t, dir)
		caPath := generateTestCA(t, dir)

		cfg, err := buildTLSConfig(certPath, keyPath, caPath, "")
		require.NoError(t, err)
		require.NotNil(t, cfg)

		assert.Equal(t, tls.RequireAndVerifyClientCert, cfg.ClientAuth)
		assert.NotNil(t, cfg.ClientCAs)
	})

	t.Run("errors on unreadable client CA", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCert(t, dir)

		_, err := buildTLSConfig(certPath, keyPath, "/nonexistent/ca.pem", "")
		require.Error(t, err)
	})

	t.Run("errors on invalid client CA PEM", func(t *testing.T) {
		dir := t.TempDir()
		certPath, keyPath := generateTestCert(t, dir)

		invalidCAPath := filepath.Join(dir, "bad-ca.pem")
		require.NoError(t, os.WriteFile(invalidCAPath, []byte("not a certificate"), 0o600))

		_, err := buildTLSConfig(certPath, keyPath, invalidCAPath, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no valid certificates")
	})
}
