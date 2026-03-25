package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
)

// buildTLSConfig constructs a *tls.Config from the given cert, key, and optional client CA paths.
// If both certFile and keyFile are empty, TLS is disabled and (nil, nil) is returned.
// When clientCAFile is provided, mutual TLS (mTLS) is enabled.
func buildTLSConfig(certFile, keyFile, clientCAFile, minVersion string) (*tls.Config, error) {
	if certFile == "" && keyFile == "" {
		return nil, nil
	}

	if certFile == "" || keyFile == "" {
		return nil, errors.New("both ORES_TLS_CERT and ORES_TLS_KEY must be set together")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("loading TLS key pair: %w", err)
	}

	minVer, err := parseTLSMinVersion(minVersion)
	if err != nil {
		return nil, err
	}

	cfg := &tls.Config{ //nolint:gosec // minVer is validated by parseTLSMinVersion to be TLS 1.2 or 1.3
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVer,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256},
	}

	if clientCAFile != "" {
		caPEM, err := os.ReadFile(clientCAFile) //nolint:gosec // path is operator-supplied configuration, not user input
		if err != nil {
			return nil, fmt.Errorf("reading client CA file: %w", err)
		}

		caPool := x509.NewCertPool()
		if !caPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("client CA file %s: no valid certificates found", clientCAFile)
		}

		cfg.ClientCAs = caPool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return cfg, nil
}

// parseTLSMinVersion converts a version string to a tls.Version constant.
// An empty string defaults to TLS 1.2.
func parseTLSMinVersion(v string) (uint16, error) {
	switch v {
	case "", "1.2":
		return tls.VersionTLS12, nil
	case "1.3":
		return tls.VersionTLS13, nil
	default:
		return 0, fmt.Errorf("unsupported TLS minimum version %q (use \"1.2\" or \"1.3\")", v)
	}
}
