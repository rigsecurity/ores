package main

import "net/http"

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
