package main

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// securityHeadersMiddleware sets security-related response headers on every request.
// When tlsEnabled is true, HSTS is also set.
func securityHeadersMiddleware(tlsEnabled bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")

		if tlsEnabled {
			w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// maxBodyMiddleware limits the size of incoming request bodies.
// If limit <= 0 the check is disabled and next is returned directly.
func maxBodyMiddleware(limit int64, next http.Handler) http.Handler {
	if limit <= 0 {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

// ipLimiter pairs a rate limiter with a last-seen timestamp for per-IP tracking.
type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// rateLimiterStore manages per-IP rate limiters with automatic cleanup of idle entries.
type rateLimiterStore struct {
	limiters sync.Map
	rps      rate.Limit
	burst    int
}

// cleanupInterval is how often stale IP entries are evicted.
const cleanupInterval = 5 * time.Minute

// idleTimeout is the maximum idle time before an IP entry is evicted.
const idleTimeout = 10 * time.Minute

// newRateLimiterStore creates a store and starts a background cleanup goroutine.
func newRateLimiterStore(rps float64, burst int) *rateLimiterStore {
	s := &rateLimiterStore{
		rps:   rate.Limit(rps),
		burst: burst,
	}

	go s.cleanup()

	return s
}

// get returns the rate limiter for the given IP, creating one if necessary.
func (s *rateLimiterStore) get(ip string) *rate.Limiter {
	now := time.Now()

	if v, ok := s.limiters.Load(ip); ok {
		entry := v.(*ipLimiter)
		entry.lastSeen = now

		return entry.limiter
	}

	limiter := rate.NewLimiter(s.rps, s.burst)
	s.limiters.Store(ip, &ipLimiter{limiter: limiter, lastSeen: now})

	return limiter
}

// cleanup periodically evicts IP entries that have been idle longer than idleTimeout.
func (s *rateLimiterStore) cleanup() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		cutoff := time.Now().Add(-idleTimeout)

		s.limiters.Range(func(key, value any) bool {
			entry := value.(*ipLimiter)
			if entry.lastSeen.Before(cutoff) {
				s.limiters.Delete(key)
			}

			return true
		})
	}
}

// rateLimitMiddleware enforces per-IP rate limiting.
// Health probes (/healthz, /readyz) are exempted.
func rateLimitMiddleware(rps float64, burst int, next http.Handler) http.Handler {
	store := newRateLimiterStore(rps, burst)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Exempt health probes from rate limiting.
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
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
