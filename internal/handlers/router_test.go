package handlers_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"backend/internal/api"
	"backend/internal/handlers"
)

const testMD5 = "d41d8cd98f00b204e9800998ecf8427e"
const minimalBody = `{"md5":"` + testMD5 + `","name":"Trojan.Win32.Generic"}`

// recordingHandler distinguishes rejected requests from requests reaching business logic.
type recordingHandler struct {
	calls       int
	create      *api.CreateThreatRequestObject
	get         *api.GetInfoByMd5RequestObject
	update      *api.UpdateThreatRequestObject
	panicOnCall bool
}

func (h *recordingHandler) result() error {
	h.calls++
	if h.panicOnCall {
		panic("private panic details")
	}
	return errors.New("private database details")
}

func (h *recordingHandler) CreateThreat(_ context.Context, r api.CreateThreatRequestObject) (api.CreateThreatResponseObject, error) {
	h.create = &r
	return nil, h.result()
}

func (h *recordingHandler) GetInfoByMd5(_ context.Context, r api.GetInfoByMd5RequestObject) (api.GetInfoByMd5ResponseObject, error) {
	h.get = &r
	return nil, h.result()
}

func (h *recordingHandler) UpdateThreat(_ context.Context, r api.UpdateThreatRequestObject) (api.UpdateThreatResponseObject, error) {
	h.update = &r
	return nil, h.result()
}

func TestRouterValidation(t *testing.T) {
	tests := []struct {
		name, method, path, body string
		status, calls            int
		detail                   string
	}{
		{name: "health", method: "GET", path: "/health", status: 200},
		{name: "health trailing slash", method: "GET", path: "/health/", status: 200},
		{name: "get valid", method: "GET", path: "/info/" + testMD5, status: 500, calls: 1},
		{name: "get uppercase hash", method: "GET", path: "/info/" + strings.ToUpper(testMD5), status: 500, calls: 1},
		{name: "get invalid hash", method: "GET", path: "/info/xyz", status: 400, detail: "md5"},
		{name: "minimal post", method: "POST", path: "/info", body: minimalBody, status: 500, calls: 1},
		{name: "missing name", method: "POST", path: "/info", body: `{"md5":"` + testMD5 + `"}`, status: 400, detail: "name"},
		{name: "invalid severity", method: "POST", path: "/info", body: strings.TrimSuffix(minimalBody, "}") + `,"severity":"extreme"}`, status: 400, detail: "severity"},
		{name: "unknown property", method: "POST", path: "/info", body: strings.TrimSuffix(minimalBody, "}") + `,"unexpected_field":"typo"}`, status: 400, detail: "unexpected_field"},
		{name: "malformed json", method: "POST", path: "/info", body: `{"md5":`, status: 400},
		{name: "missing body", method: "POST", path: "/info", status: 400},
		{name: "oversized body", method: "POST", path: "/info", body: strings.Repeat("x", 64*1024+1), status: 413},
		{name: "valid put", method: "PUT", path: "/info/" + testMD5, body: `{"name":"Trojan.Win32.Generic"}`, status: 500, calls: 1},
		{name: "put forbids body md5", method: "PUT", path: "/info/" + testMD5, body: minimalBody, status: 400, detail: "md5"},
		{name: "unsupported method", method: "PATCH", path: "/info/" + testMD5, status: 405},
		{name: "unknown path", method: "GET", path: "/nope", status: 404},
		{name: "health unsupported method", method: "POST", path: "/health", status: 405},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := &recordingHandler{}
			e, err := handlers.NewRouter(zap.NewNop().Sugar(), h)
			require.NoError(t, err)
			req := httptest.NewRequest(tt.method, "http://127.0.0.1:8000"+tt.path, strings.NewReader(tt.body))
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			require.Equal(t, tt.status, rec.Code, rec.Body.String())
			require.Equal(t, tt.calls, h.calls)
			require.Contains(t, rec.Header().Get("Content-Type"), "application/json")
			require.NotEmpty(t, rec.Header().Get("X-Request-ID"))
			if tt.status == http.StatusOK {
				require.JSONEq(t, `{"status":"ok"}`, rec.Body.String())
				return
			}
			var resp api.ErrorResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
			require.NotNil(t, resp.Message)
			require.NotEmpty(t, *resp.Message)
			if tt.detail != "" {
				require.NotNil(t, resp.Details)
				require.Contains(t, *resp.Details, tt.detail)
			}
			if tt.status == http.StatusInternalServerError {
				require.Nil(t, resp.Details)
				require.NotContains(t, rec.Body.String(), "private database details")
			}
		})
	}
}

func TestRouterBindsStrictRequests(t *testing.T) {
	h := &recordingHandler{}
	e, err := handlers.NewRouter(zap.NewNop().Sugar(), h)
	require.NoError(t, err)

	body := strings.TrimSuffix(minimalBody, "}") + `,"severity":"high","file_size":0,"tags":["apt"]}`
	req := httptest.NewRequest(http.MethodPost, "http://db-independent:9000/info", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	e.ServeHTTP(httptest.NewRecorder(), req)
	require.NotNil(t, h.create)
	require.NotNil(t, h.create.Body)
	require.Equal(t, testMD5, h.create.Body.Md5)
	require.Equal(t, "Trojan.Win32.Generic", h.create.Body.Name)
	require.NotNil(t, h.create.Body.Severity)
	require.Equal(t, api.Severity("high"), *h.create.Body.Severity)
	require.NotNil(t, h.create.Body.FileSize)
	require.Zero(t, *h.create.Body.FileSize)

	e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/info/"+strings.ToUpper(testMD5), http.NoBody))
	require.NotNil(t, h.get)
	require.Equal(t, strings.ToUpper(testMD5), h.get.Md5)

	req = httptest.NewRequest(http.MethodPut, "/info/"+testMD5, strings.NewReader(`{"name":"Backdoor.AndroidOS.Triada.a"}`))
	req.Header.Set("Content-Type", "application/json")
	e.ServeHTTP(httptest.NewRecorder(), req)
	require.NotNil(t, h.update)
	require.Equal(t, testMD5, h.update.Md5)
	require.NotNil(t, h.update.Body)
	require.Equal(t, "Backdoor.AndroidOS.Triada.a", h.update.Body.Name)
	require.Equal(t, 3, h.calls)
}

func TestRouterRecoversPanic(t *testing.T) {
	h := &recordingHandler{panicOnCall: true}
	e, err := handlers.NewRouter(zap.NewNop().Sugar(), h)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/info/"+testMD5, http.NoBody))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.JSONEq(t, `{"message":"Internal server error"}`, rec.Body.String())
	require.NotContains(t, rec.Body.String(), "private panic details")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", http.NoBody))
	require.Equal(t, http.StatusOK, rec.Code)
}
