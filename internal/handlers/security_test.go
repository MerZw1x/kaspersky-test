package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"backend/internal/api"
	"backend/internal/config"
	"backend/internal/handlers"
)

const readerKey = "test-reader-key-at-least-16"
const writerKey = "test-writer-key-at-least-16"

func TestRouterAPIKeys(t *testing.T) {
	for _, tt := range []struct {
		name, method, path, body string
		keys                     []string
		status, calls            int
	}{
		{name: "missing", method: "GET", path: "/info/" + testMD5, status: 401},
		{name: "wrong", method: "GET", path: "/info/" + testMD5, keys: []string{"invalid"}, status: 401},
		{name: "reader get", method: "GET", path: "/info/" + testMD5, keys: []string{readerKey}, status: 500, calls: 1},
		{name: "writer get", method: "GET", path: "/info/" + testMD5, keys: []string{writerKey}, status: 500, calls: 1},
		{name: "writer post", method: "POST", path: "/info", body: minimalBody, keys: []string{writerKey}, status: 500, calls: 1},
		{name: "writer put", method: "PUT", path: "/info/" + testMD5, body: `{"name":"Trojan.Win32.Generic"}`, keys: []string{writerKey}, status: 500, calls: 1},
		{name: "reader post", method: "POST", path: "/info", body: minimalBody, keys: []string{readerKey}, status: 403},
		{name: "reader put", method: "PUT", path: "/info/" + testMD5, body: `{"name":"Trojan.Win32.Generic"}`, keys: []string{readerKey}, status: 403},
		{name: "duplicate header", method: "GET", path: "/info/" + testMD5, keys: []string{readerKey, writerKey}, status: 401},
		{name: "oversized key", method: "GET", path: "/info/" + testMD5, keys: []string{strings.Repeat("x", 257)}, status: 401},
		{name: "health without key", method: "GET", path: "/health", status: 200},
	} {
		t.Run(tt.name, func(t *testing.T) {
			h := &recordingHandler{}
			e, err := handlers.NewRouter(zap.NewNop().Sugar(), h, handlers.RouterOptions{Security: config.SecurityConfig{
				Auth: config.AuthConfig{Enabled: true, ReaderKey: readerKey, WriterKey: writerKey},
			}})
			require.NoError(t, err)
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			for _, key := range tt.keys {
				req.Header.Add("X-API-Key", key)
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			require.Equal(t, tt.status, rec.Code, rec.Body.String())
			require.Equal(t, tt.calls, h.calls)
			require.NotContains(t, rec.Body.String(), readerKey)
			require.NotContains(t, rec.Body.String(), writerKey)
			if tt.status >= 400 {
				var body api.ErrorResponse
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
				require.NotNil(t, body.Message)
			}
		})
	}
}

func TestRouterRateLimit(t *testing.T) {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	h := &recordingHandler{}
	e, err := handlers.NewRouter(zap.NewNop().Sugar(), h, handlers.RouterOptions{
		Now: func() time.Time { return now }, Security: config.SecurityConfig{RateLimit: config.RateLimitConfig{
			Enabled: true, RequestsPerSecond: 1, Burst: 1, MaxClients: 2, IdleTTL: time.Minute,
		}},
	})
	require.NoError(t, err)
	request := func(ip, xff, path string, status int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
		req.RemoteAddr = ip + ":12345"
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set("X-Real-IP", xff)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		require.Equal(t, status, rec.Code, rec.Body.String())
		return rec
	}
	path := "/info/" + testMD5
	request("192.0.2.1", "198.51.100.1", path, 500)
	blocked := request("192.0.2.1", "198.51.100.2", path, 429)
	require.Equal(t, "1", blocked.Header().Get("Retry-After"))
	require.JSONEq(t, `{"message":"Too Many Requests","details":"request rate limit exceeded"}`, blocked.Body.String())
	request("192.0.2.2", "198.51.100.2", path, 500)
	request("192.0.2.3", "", path, 429)
	for range 5 {
		request("192.0.2.1", "", "/health", 200)
	}
	now = now.Add(time.Second)
	request("192.0.2.1", "", path, 500)
	now = now.Add(2 * time.Minute)
	request("192.0.2.3", "", path, 500)
	require.Equal(t, 4, h.calls)
}

func TestRateLimitAppliesBeforeAuthentication(t *testing.T) {
	h := &recordingHandler{}
	e, err := handlers.NewRouter(zap.NewNop().Sugar(), h, handlers.RouterOptions{Security: config.SecurityConfig{
		Auth:      config.AuthConfig{Enabled: true, ReaderKey: readerKey, WriterKey: writerKey},
		RateLimit: config.RateLimitConfig{Enabled: true, RequestsPerSecond: 1, Burst: 1, MaxClients: 2, IdleTTL: time.Minute},
	}})
	require.NoError(t, err)
	for _, status := range []int{401, 429} {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/info/"+testMD5, http.NoBody))
		require.Equal(t, status, rec.Code, rec.Body.String())
	}
	require.Zero(t, h.calls)
}
