// Package main is the entry point for the ORES daemon (oresd).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rigsecurity/ores/gen/proto/ores/v1/oresv1connect"
	"github.com/rigsecurity/ores/pkg/engine"
)

const (
	defaultPort       = ":8080"
	shutdownTimeout   = 15 * time.Second
	readHeaderTimeout = 10 * time.Second
	readTimeout       = 30 * time.Second
	writeTimeout      = 30 * time.Second
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	port := os.Getenv("ORES_PORT")
	if port == "" {
		port = defaultPort
	}

	e := engine.New()
	h := &OresHandler{engine: e}

	mux := newMux(h, logger)

	srv := &http.Server{
		Addr:              port,
		Handler:           mux,
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
		logger.Info("oresd starting", "addr", port)

		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
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
