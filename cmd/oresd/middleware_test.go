package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// echoBodyHandler reads and echoes the request body so that MaxBytesReader can trigger.
var echoBodyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	_, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)

		return
	}

	w.WriteHeader(http.StatusOK)
})

func TestMaxBodyMiddleware(t *testing.T) {
	t.Run("allows requests within limit", func(t *testing.T) {
		handler := maxBodyMiddleware(1024, echoBodyHandler)
		body := strings.NewReader("hello")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", body))

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("rejects requests exceeding limit", func(t *testing.T) {
		handler := maxBodyMiddleware(5, echoBodyHandler)
		body := strings.NewReader("this body exceeds the five byte limit")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", body))

		assert.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	})

	t.Run("zero limit disables check", func(t *testing.T) {
		handler := maxBodyMiddleware(0, echoBodyHandler)
		body := strings.NewReader(strings.Repeat("x", 10000))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/", body))

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("negative limit disables check", func(t *testing.T) {
		handler := maxBodyMiddleware(-1, echoBodyHandler)
		require.IsType(t, echoBodyHandler, handler)
	})
}
