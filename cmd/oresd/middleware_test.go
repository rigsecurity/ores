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

func TestRateLimitMiddleware(t *testing.T) {
	t.Run("allows requests under limit", func(t *testing.T) {
		handler := rateLimitMiddleware(10, 10, okHandler)
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "192.168.1.1:12345"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("blocks when rate exceeded", func(t *testing.T) {
		// Allow 1 request with burst of 1 — the second request should be rejected.
		handler := rateLimitMiddleware(1, 1, okHandler)

		req1 := httptest.NewRequest(http.MethodGet, "/test", nil)
		req1.RemoteAddr = "10.0.0.1:1111"
		rec1 := httptest.NewRecorder()
		handler.ServeHTTP(rec1, req1)
		assert.Equal(t, http.StatusOK, rec1.Code)

		req2 := httptest.NewRequest(http.MethodGet, "/test", nil)
		req2.RemoteAddr = "10.0.0.1:2222"
		rec2 := httptest.NewRecorder()
		handler.ServeHTTP(rec2, req2)
		assert.Equal(t, http.StatusTooManyRequests, rec2.Code)
		assert.Equal(t, "1", rec2.Header().Get("Retry-After"))
	})

	t.Run("exempts healthz", func(t *testing.T) {
		handler := rateLimitMiddleware(1, 1, okHandler)

		// Exhaust the limiter with a normal request.
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.2:1111"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Health probe should still pass.
		hReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		hReq.RemoteAddr = "10.0.0.2:2222"
		hRec := httptest.NewRecorder()
		handler.ServeHTTP(hRec, hReq)
		assert.Equal(t, http.StatusOK, hRec.Code)
	})

	t.Run("exempts readyz", func(t *testing.T) {
		handler := rateLimitMiddleware(1, 1, okHandler)

		// Exhaust the limiter with a normal request.
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		req.RemoteAddr = "10.0.0.3:1111"
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		// Readiness probe should still pass.
		rReq := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		rReq.RemoteAddr = "10.0.0.3:2222"
		rRec := httptest.NewRecorder()
		handler.ServeHTTP(rRec, rReq)
		assert.Equal(t, http.StatusOK, rRec.Code)
	})
}
