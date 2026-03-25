package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	oresv1 "github.com/rigsecurity/ores/gen/proto/ores/v1"
	"github.com/rigsecurity/ores/gen/proto/ores/v1/oresv1connect"
	"github.com/rigsecurity/ores/pkg/engine"
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
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
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

func TestTLSServerIntegration(t *testing.T) {
	// 1. Generate a self-signed cert.
	dir := t.TempDir()
	certPath, keyPath := generateTestCert(t, dir)

	// 2. Build a TLS config.
	tlsCfg, err := buildTLSConfig(certPath, keyPath, "", "")
	require.NoError(t, err)
	require.NotNil(t, tlsCfg)

	// 3. Create a real OresHandler backed by engine.New().
	e := engine.New()
	h := &OresHandler{engine: e}

	// 4. Build the mux and wrap with middleware (TLS enabled).
	logger := slog.New(slog.DiscardHandler)
	mux := newMux(h, logger)
	wrapped := applyMiddleware(mux, muxOptions{
		maxBodyBytes: defaultMaxBodyBytes,
		tlsEnabled:   true,
	})

	// 5. Create an httptest TLS server.
	srv := httptest.NewUnstartedServer(wrapped)
	srv.TLS = tlsCfg
	srv.StartTLS()
	t.Cleanup(srv.Close)

	// 6. Create a ConnectRPC client using the test server's TLS client.
	client := oresv1connect.NewOresServiceClient(
		srv.Client(),
		srv.URL,
		connect.WithSendCompression("identity"),
	)

	// 7. Call Evaluate with a valid request.
	signals, err := structpb.NewStruct(map[string]any{
		"cvss": map[string]any{"base_score": 7.5},
	})
	require.NoError(t, err)

	resp, err := client.Evaluate(context.Background(), connect.NewRequest(&oresv1.EvaluateRequest{
		ApiVersion: "ores.dev/v1",
		Kind:       "EvaluationRequest",
		Signals:    signals,
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg)

	// 8. Assert score is in [0, 100].
	assert.GreaterOrEqual(t, resp.Msg.Score, int32(0))
	assert.LessOrEqual(t, resp.Msg.Score, int32(100))

	// 9. Verify security headers on /healthz via plain HTTP GET.
	healthResp, err := srv.Client().Get(srv.URL + "/healthz")
	require.NoError(t, err)
	defer healthResp.Body.Close() //nolint:errcheck // best-effort close in test

	assert.Equal(t, http.StatusOK, healthResp.StatusCode)
	assert.Equal(t, "nosniff", healthResp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "max-age=63072000; includeSubDomains", healthResp.Header.Get("Strict-Transport-Security"))
}
