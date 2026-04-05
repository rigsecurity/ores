package main

import (
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rigsecurity/ores/gen/proto/ores/v1/oresv1connect"
	"golang.org/x/time/rate"
)

// Probe paths used by Kubernetes liveness/readiness checks.
// Shared between mux registration and rate limiter exemption.
const (
	healthzPath = "/healthz"
	readyzPath  = "/readyz"
)

// HSTS header value: 2 years, include subdomains.
const hstsValue = "max-age=63072000; includeSubDomains"

// muxOptions holds configuration for the middleware chain.
type muxOptions struct {
	maxBodyBytes int64
	rateLimitRPS float64
	rateBurst    int
	tlsEnabled   bool
	corsOrigins  []string
}

// applyMiddleware wraps a handler with the full middleware chain.
// Order (outermost first): maxBody -> rateLimit -> securityHeaders -> cors.
func applyMiddleware(handler http.Handler, opts muxOptions) http.Handler {
	h := handler

	// CORS (innermost of our chain).
	h = corsMiddleware(opts.corsOrigins, h)

	// Security headers.
	h = securityHeadersMiddleware(opts.tlsEnabled, h)

	// Rate limiting (only if enabled).
	if opts.rateLimitRPS > 0 {
		burst := opts.rateBurst
		if burst < 1 {
			burst = max(int(opts.rateLimitRPS), 1)
		}

		h = rateLimitMiddleware(opts.rateLimitRPS, burst, h)
	}

	// Max body size (outermost).
	h = maxBodyMiddleware(opts.maxBodyBytes, h)

	return h
}

// parseCORSOrigins splits a comma-separated string of origins.
// Returns nil for empty input. Logs warnings for likely misconfigurations.
func parseCORSOrigins(logger *slog.Logger, s string) []string {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, ",")
	origins := make([]string, 0, len(parts))
	hasWildcard := false

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		if p == "*" {
			hasWildcard = true
		} else if !strings.HasPrefix(p, "http://") && !strings.HasPrefix(p, "https://") {
			logger.Warn("CORS origin missing scheme — browsers send Origin with scheme, this may not match",
				"origin", p)
		}

		origins = append(origins, p)
	}

	if len(origins) == 0 {
		return nil
	}

	if hasWildcard && len(origins) > 1 {
		logger.Warn("CORS wildcard '*' combined with specific origins — wildcard takes precedence, other origins are ignored")
	}

	return origins
}

// securityHeadersMiddleware sets security-related response headers on every request.
// When tlsEnabled is true, HSTS is also set.
func securityHeadersMiddleware(tlsEnabled bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")

		if tlsEnabled {
			w.Header().Set("Strict-Transport-Security", hstsValue)
		}

		next.ServeHTTP(w, r)
	})
}

// maxBodyMiddleware limits the size of incoming request bodies.
// If limit is 0 the check is disabled and next is returned directly.
func maxBodyMiddleware(limit int64, next http.Handler) http.Handler {
	if limit == 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// ipLimiter pairs a rate limiter with an atomic last-seen unix timestamp for per-IP tracking.
type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64 // unix timestamp
}

// rateLimiterStore manages per-IP rate limiters with automatic cleanup of idle entries.
type rateLimiterStore struct {
	limiters sync.Map
	rps      rate.Limit
	burst    int
	done     chan struct{}
}

// cleanupInterval is how often stale IP entries are evicted.
const cleanupInterval = 5 * time.Minute

// idleTimeout is the maximum idle time before an IP entry is evicted.
const idleTimeout = 10 * time.Minute

// newRateLimiterStore creates a store and starts a background cleanup goroutine.
// Close the returned store's done channel to stop the cleanup goroutine.
func newRateLimiterStore(rps float64, burst int) *rateLimiterStore {
	s := &rateLimiterStore{
		rps:   rate.Limit(rps),
		burst: burst,
		done:  make(chan struct{}),
	}

	go s.cleanup()

	return s
}

// get returns the rate limiter for the given IP, creating one if necessary.
// Uses LoadOrStore to avoid a race where two goroutines both create a limiter
// for the same new IP, effectively doubling the burst allowance.
func (s *rateLimiterStore) get(ip string) *rate.Limiter {
	now := time.Now().Unix()

	// Fast path: IP already tracked.
	if v, ok := s.limiters.Load(ip); ok {
		entry := v.(*ipLimiter)
		entry.lastSeen.Store(now)

		return entry.limiter
	}

	// Slow path: new IP — use LoadOrStore to ensure exactly one limiter wins.
	entry := &ipLimiter{limiter: rate.NewLimiter(s.rps, s.burst)}
	entry.lastSeen.Store(now)

	actual, _ := s.limiters.LoadOrStore(ip, entry)
	winner := actual.(*ipLimiter)
	winner.lastSeen.Store(now)

	return winner.limiter
}

// cleanup periodically evicts IP entries that have been idle longer than idleTimeout.
// It stops when the done channel is closed.
func (s *rateLimiterStore) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-idleTimeout).Unix()

			s.limiters.Range(func(key, value any) bool {
				entry := value.(*ipLimiter)
				if entry.lastSeen.Load() < cutoff {
					s.limiters.Delete(key)
				}

				return true
			})
		}
	}
}

// rateLimitMiddleware enforces per-IP rate limiting.
// Health probes (/healthz, /readyz) are exempted.
func rateLimitMiddleware(rps float64, burst int, next http.Handler) http.Handler {
	store := newRateLimiterStore(rps, burst)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exempt health probes from rate limiting.
		if r.URL.Path == healthzPath || r.URL.Path == readyzPath {
			next.ServeHTTP(w, r)

			return
		}

		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}

		if !store.get(ip).Allow() {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)

			return
		}

		next.ServeHTTP(w, r)
	})
}

// corsMiddleware adds CORS headers for the specified allowed origins.
// If origins is nil or empty, CORS is disabled and next is returned directly.
// A wildcard "*" in the origins list allows any origin.
func corsMiddleware(origins []string, next http.Handler) http.Handler {
	if len(origins) == 0 {
		return next
	}

	wildcard := false
	allowed := make(map[string]struct{}, len(origins))

	for _, o := range origins {
		if o == "*" {
			wildcard = true
		}

		allowed[o] = struct{}{}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		var matchedOrigin string

		switch {
		case wildcard:
			matchedOrigin = "*"
		case origin != "":
			if _, ok := allowed[origin]; ok {
				matchedOrigin = origin
			}
		}

		if matchedOrigin == "" {
			next.ServeHTTP(w, r)

			return
		}

		w.Header().Set("Access-Control-Allow-Origin", matchedOrigin)

		// Non-wildcard responses vary by Origin so caches don't serve wrong CORS headers.
		if !wildcard {
			w.Header().Set("Vary", "Origin")
		}

		// Handle preflight OPTIONS requests.
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Connect-Protocol-Version, Grpc-Timeout")
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)

			return
		}

		next.ServeHTTP(w, r)
	})
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
			"remote_addr", r.RemoteAddr,
			"status", rw.statusCode,
			"latency_ms", time.Since(start).Milliseconds(),
		)
	})
}

// responseRecorder wraps http.ResponseWriter to capture the status code.
// It delegates Flush to the underlying writer so HTTP/2 and gRPC streaming work correctly.
type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (rr *responseRecorder) WriteHeader(code int) {
	rr.statusCode = code
	rr.ResponseWriter.WriteHeader(code)
}

// Flush delegates to the underlying ResponseWriter if it implements http.Flusher.
// This is required for HTTP/2 and gRPC streaming support.
func (rr *responseRecorder) Flush() {
	if f, ok := rr.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
