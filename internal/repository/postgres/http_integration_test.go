//go:build integration

package postgres_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"backend/internal/api"
	"backend/internal/config"
	"backend/internal/handlers"
	v1 "backend/internal/handlers/v1"
	"backend/internal/repository/postgres"
	"backend/internal/service"
)

func TestHTTPPostgres(t *testing.T) {
	db, _ := setupDB(t)
	now := record(1).CreatedAt
	svc := service.NewThreatService(postgres.NewThreatRepository(db), func() time.Time { return now })
	router, err := handlers.NewRouter(zap.NewNop().Sugar(), v1.NewThreatHandler(svc))
	require.NoError(t, err)
	spec, err := api.GetSwagger()
	require.NoError(t, err)
	spec.Servers = nil
	specRouter, err := gorillamux.NewRouter(spec)
	require.NoError(t, err)

	request := func(method, path, body string, status int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "http://127.0.0.1:8000"+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		require.Equal(t, status, rec.Code, rec.Body.String())
		// Проверяем ответ по той же спецификации, из которой сгенерирован сервер.
		route, params, findErr := specRouter.FindRoute(req)
		require.NoError(t, findErr)
		validation := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req, PathParams: params, Route: route},
			Status:                 rec.Code, Header: rec.Header(), Options: &openapi3filter.Options{IncludeResponseStatus: true},
		}
		validation.SetBodyBytes(rec.Body.Bytes())
		require.NoError(t, openapi3filter.ValidateResponse(context.Background(), validation))
		return rec
	}
	decode := func(rec *httptest.ResponseRecorder) api.ThreatResponse {
		t.Helper()
		var body api.ThreatResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		return body
	}

	key := strings.Repeat("abcdef", 5) + "ab"
	path := "/info/" + key
	createBody := `{"md5":"` + strings.ToUpper(key) + `","name":"Trojan.Win32.Generic","sha256":"` + strings.Repeat("A", 64) + `","file_size":0,"description":"Описание","tags":["apt"],"severity":"high","first_seen":"2026-10-19T12:00:00Z","last_seen":"2026-10-20T12:00:00Z"}`
	created := decode(request(http.MethodPost, "/info", createBody, http.StatusCreated))
	require.Equal(t, key, created.Md5)
	require.Equal(t, strings.Repeat("a", 64), *created.Sha256)
	require.Zero(t, *created.FileSize)
	require.Equal(t, api.Severity("high"), created.Severity)
	require.Equal(t, api.ThreatType("unknown"), created.Type)
	require.Equal(t, now, created.CreatedAt)
	require.Equal(t, created, decode(request(http.MethodGet, path, "", http.StatusOK)))

	request(http.MethodPost, "/info", `{"md5":"`+key+`","name":"Trojan.Win32.Generic"}`, http.StatusConflict)
	now = now.Add(time.Hour)
	updated := decode(request(http.MethodPut, path, `{"name":"Backdoor.AndroidOS.Triada.a"}`, http.StatusOK))
	require.Equal(t, "Backdoor.AndroidOS.Triada.a", updated.Name)
	require.Equal(t, created.CreatedAt, updated.CreatedAt)
	require.Equal(t, now, updated.UpdatedAt)
	require.Equal(t, api.Severity("unknown"), updated.Severity)
	require.Equal(t, api.ThreatStatus("active"), updated.Status)
	require.Empty(t, updated.Tags)
	require.NotNil(t, updated.Tags)
	require.Nil(t, updated.Sha256)
	require.Nil(t, updated.FileSize)
	require.Nil(t, updated.Description)
	require.Nil(t, updated.FirstSeen)
	require.Nil(t, updated.LastSeen)
	require.Equal(t, updated, decode(request(http.MethodGet, "/info/"+strings.ToUpper(key), "", http.StatusOK)))

	missing := "/info/" + strings.Repeat("0", 32)
	request(http.MethodGet, missing, "", http.StatusNotFound)
	request(http.MethodPut, missing, `{"name":"Trojan.Win32.Generic"}`, http.StatusNotFound)
	request(http.MethodGet, "/info/xyz", "", http.StatusBadRequest)
	request(http.MethodPut, path, `{"name":"Trojan.Win32.Generic","first_seen":"2026-10-20T12:00:00Z","last_seen":"2026-10-19T12:00:00Z"}`, http.StatusBadRequest)
	request(http.MethodPost, "/info", `{"md5":"`+strings.Repeat("b", 32)+`","name":"Trojan.Win32.Generic","first_seen":"2099-01-01T00:00:00Z"}`, http.StatusBadRequest)
	require.Equal(t, updated, decode(request(http.MethodGet, path, "", http.StatusOK)))

	require.NoError(t, db.Close())
	failed := request(http.MethodGet, path, "", http.StatusInternalServerError)
	require.JSONEq(t, `{"message":"Internal server error"}`, failed.Body.String())
}

func TestSecureHTTPPostgres(t *testing.T) {
	db, _ := setupDB(t)
	const reader = "integration-reader-secret-key"
	const writer = "integration-writer-secret-key"
	svc := service.NewThreatService(postgres.NewThreatRepository(db), time.Now)
	settings := config.SecurityConfig{
		Auth:      config.AuthConfig{Enabled: true, ReaderKey: reader, WriterKey: writer},
		RateLimit: config.RateLimitConfig{Enabled: true, RequestsPerSecond: 100, Burst: 100, MaxClients: 100, IdleTTL: time.Minute},
	}
	router, err := handlers.NewRouter(zap.NewNop().Sugar(), v1.NewThreatHandler(svc), handlers.RouterOptions{Security: settings})
	require.NoError(t, err)
	spec, err := api.GetSwagger()
	require.NoError(t, err)
	spec.Servers = nil
	specRouter, err := gorillamux.NewRouter(spec)
	require.NoError(t, err)
	request := func(method, path, body, key string, status int) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if key != "" {
			req.Header.Set("X-API-Key", key)
		}
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		require.Equal(t, status, rec.Code, rec.Body.String())
		require.NotContains(t, rec.Body.String(), reader)
		require.NotContains(t, rec.Body.String(), writer)
		if path != "/health" {
			route, params, findErr := specRouter.FindRoute(req)
			require.NoError(t, findErr)
			validation := &openapi3filter.ResponseValidationInput{
				RequestValidationInput: &openapi3filter.RequestValidationInput{Request: req, Route: route, PathParams: params},
				Status:                 status, Header: rec.Header(), Options: &openapi3filter.Options{IncludeResponseStatus: true},
			}
			validation.SetBodyBytes(rec.Body.Bytes())
			require.NoError(t, openapi3filter.ValidateResponse(context.Background(), validation))
		}
	}
	key := strings.Repeat("ab", 16)
	path := "/info/" + key
	body := `{"md5":"` + key + `","name":"Trojan.Win32.Generic"}`
	request("GET", "/health", "", "", 200)
	request("GET", path, "", "", 401)
	request("GET", path, "", "wrong-key", 401)
	request("POST", "/info", body, reader, 403)
	request("POST", "/info", body, writer, 201)
	request("GET", path, "", reader, 200)
	request("POST", "/info", body, writer, 409)
	request("PUT", path, `{"name":"Backdoor.AndroidOS.Triada.a"}`, reader, 403)
	request("PUT", path, `{"name":"Backdoor.AndroidOS.Triada.a"}`, writer, 200)
	request("POST", "/info", strings.Repeat("x", 64*1024+1), writer, 413)
	settings.RateLimit.Burst = 1
	router, err = handlers.NewRouter(zap.NewNop().Sugar(), v1.NewThreatHandler(svc), handlers.RouterOptions{Security: settings, Now: func() time.Time { return time.Unix(0, 0) }})
	require.NoError(t, err)
	request("GET", path, "", reader, 200)
	request("GET", path, "", reader, 429)
	request("GET", "/health", "", "", 200)
}
