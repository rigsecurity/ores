// Package main is the entry point for the ORES daemon (oresd).
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/rigsecurity/ores/gen/proto/ores/v1/oresv1connect"
	"github.com/rigsecurity/ores/pkg/engine"
)

const (
	defaultPort         = ":8080"
	defaultMaxBodyBytes = 1 << 20 // 1 MiB
	shutdownTimeout     = 15 * time.Second
	readHeaderTimeout   = 10 * time.Second
	readTimeout         = 30 * time.Second
	writeTimeout        = 30 * time.Second
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	port := os.Getenv("ORES_PORT")
	if port == "" {
		port = defaultPort
	}

	// TLS configuration.
	tlsCfg, err := buildTLSConfig(
		os.Getenv("ORES_TLS_CERT"),
		os.Getenv("ORES_TLS_KEY"),
		os.Getenv("ORES_TLS_CLIENT_CA"),
		os.Getenv("ORES_TLS_MIN_VERSION"),
	)
	if err != nil {
		logger.Error("TLS configuration error", "err", err)
		os.Exit(1) //nolint:gocritic // intentional: no cleanup needed on startup failure
	}

	tlsEnabled := tlsCfg != nil
	mtlsEnabled := tlsEnabled && tlsCfg.ClientAuth == tls.RequireAndVerifyClientCert

	// Middleware options.
	opts := muxOptions{
		maxBodyBytes: envInt64(logger, "ORES_MAX_REQUEST_BYTES", defaultMaxBodyBytes),
		rateLimitRPS: envFloat64(logger, "ORES_RATE_LIMIT", 0),
		rateBurst:    int(envInt64(logger, "ORES_RATE_BURST", 0)),
		tlsEnabled:   tlsEnabled,
		corsOrigins:  parseCORSOrigins(os.Getenv("ORES_CORS_ORIGINS")),
	}

	e := engine.New()
	h := &OresHandler{engine: e}

	mux := newMux(h, logger)
	handler := applyMiddleware(mux, opts)

	srv := &http.Server{
		Addr:              port,
		Handler:           handler,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		BaseContext: func(_ net.Listener) context.Context {
			return context.Background()
		},
	}

	// Start in background.
	errCh := make(chan error, 1)

	go func() {
		logger.Info("oresd starting", "addr", port, "tls", tlsEnabled, "mtls", mtlsEnabled)

		var listenErr error
		if tlsEnabled {
			listenErr = srv.ListenAndServeTLS("", "") // certs already in TLSConfig
		} else {
			listenErr = srv.ListenAndServe()
		}

		if listenErr != nil && !errors.Is(listenErr, http.ErrServerClosed) {
			errCh <- listenErr
		}

		close(errCh)
	}()

	// Wait for signal or error.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil {
			logger.Error("server error", "err", err)
			os.Exit(1) //nolint:gocritic // intentional: no cleanup needed on startup failure
		}
	case sig := <-quit:
		logger.Info("shutting down", "signal", sig.String())
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		// Allow defer to run before process exit; use return with non-zero exit via deferred func.
		os.Exit(1) //nolint:gocritic // cancel() is a no-op after Shutdown completes or times out
	}

	logger.Info("oresd stopped")
}

// envInt64 reads an environment variable as int64, returning def if unset.
// Logs a warning if the value is set but unparseable.
func envInt64(logger *slog.Logger, key string, def int64) int64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}

	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		logger.Warn("invalid env var, using default", "key", key, "value", v, "default", def, "err", err)

		return def
	}

	return n
}

// envFloat64 reads an environment variable as float64, returning def if unset.
// Logs a warning if the value is set but unparseable.
func envFloat64(logger *slog.Logger, key string, def float64) float64 {
	v := os.Getenv(key)
	if v == "" {
		return def
	}

	n, err := strconv.ParseFloat(v, 64)
	if err != nil {
		logger.Warn("invalid env var, using default", "key", key, "value", v, "default", def, "err", err)

		return def
	}

	return n
}

// newMux builds the HTTP mux with ConnectRPC handlers, health/readiness endpoints,
// and audit-logging middleware.
func newMux(h *OresHandler, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	// ConnectRPC handler.
	path, connectHandler := oresv1connect.NewOresServiceHandler(h)
	mux.Handle(path, auditMiddleware(logger, connectHandler))

	// Health and readiness probes.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return mux
}

// auditMiddleware logs every Evaluate RPC with status and latency.
// Non-Evaluate calls are passed through unmodified.
func auditMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != oresv1connect.OresServiceEvaluateProcedure {
			next.ServeHTTP(w, r)

			return
		}

		rw := &responseRecorder{ResponseWriter: w, statusCode: http.StatusOK}
		start := time.Now()

		next.ServeHTTP(rw, r)

		logger.Info("audit",
			"procedure", r.URL.Path,
			"status", rw.statusCode,
			"latency_ms", time.Since(start).Milliseconds(),
		)
	})
}

// responseRecorder wraps http.ResponseWriter to capture the status code.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}
