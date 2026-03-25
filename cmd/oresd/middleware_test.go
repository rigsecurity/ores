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

func TestCORSMiddleware(t *testing.T) {
	t.Run("no origins disables CORS", func(t *testing.T) {
		handler := corsMiddleware(nil, okHandler)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", "https://example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("wildcard allows any origin", func(t *testing.T) {
		handler := corsMiddleware([]string{"*"}, okHandler)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", "https://anything.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("specific origin matched", func(t *testing.T) {
		handler := corsMiddleware([]string{"https://app.example.com"}, okHandler)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", "https://app.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "https://app.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("non-matching origin gets no CORS headers", func(t *testing.T) {
		handler := corsMiddleware([]string{"https://allowed.example.com"}, okHandler)
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("preflight returns 204 with all headers", func(t *testing.T) {
		handler := corsMiddleware([]string{"https://app.example.com"}, okHandler)
		req := httptest.NewRequest(http.MethodOptions, "/", nil)
		req.Header.Set("Origin", "https://app.example.com")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "https://app.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "POST, GET, OPTIONS", rec.Header().Get("Access-Control-Allow-Methods"))
		assert.Equal(t, "Content-Type, Connect-Protocol-Version, Grpc-Timeout", rec.Header().Get("Access-Control-Allow-Headers"))
		assert.Equal(t, "86400", rec.Header().Get("Access-Control-Max-Age"))
	})
}
