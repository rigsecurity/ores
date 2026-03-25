package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// noop handler for middleware tests.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestSecurityHeadersMiddleware(t *testing.T) {
	t.Run("base headers always set", func(t *testing.T) {
		handler := securityHeadersMiddleware(false, okHandler)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
		assert.Equal(t, "default-src 'none'", rec.Header().Get("Content-Security-Policy"))
	})

	t.Run("HSTS added when TLS enabled", func(t *testing.T) {
		handler := securityHeadersMiddleware(true, okHandler)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		assert.Equal(t, "max-age=63072000; includeSubDomains", rec.Header().Get("Strict-Transport-Security"))
	})

	t.Run("HSTS absent when TLS disabled", func(t *testing.T) {
		handler := securityHeadersMiddleware(false, okHandler)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

		assert.Empty(t, rec.Header().Get("Strict-Transport-Security"))
	})
}
