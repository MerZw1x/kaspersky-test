package v1_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"backend/internal/api"
	"backend/internal/domain"
	errs "backend/internal/errors"
	"backend/internal/handlers"
	v1 "backend/internal/handlers/v1"
)

const hash = "d41d8cd98f00b204e9800998ecf8427e"
const name = "Trojan.Win32.Generic"

type fakeService struct {
	result domain.Threat
	err    error
	calls  int
	method string
	key    string
	input  domain.ThreatInput
	ctx    context.Context
}

func (s *fakeService) Create(ctx context.Context, key string, input domain.ThreatInput) (domain.Threat, error) {
	s.method = "create"
	s.key = key
	s.input = input
	s.ctx = ctx
	s.calls++
	return s.result, s.err
}
func (s *fakeService) GetByMD5(ctx context.Context, key string) (domain.Threat, error) {
	s.method = "get"
	s.key = key
	s.ctx = ctx
	s.calls++
	return s.result, s.err
}
func (s *fakeService) Update(ctx context.Context, key string, input domain.ThreatInput) (domain.Threat, error) {
	s.method = "update"
	s.key = key
	s.input = input
	s.ctx = ctx
	s.calls++
	return s.result, s.err
}

func fullThreat() domain.Threat {
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	return domain.Threat{
		MD5: hash, Name: name, Type: domain.ThreatTypeTrojan, Platform: domain.PlatformWindows,
		Severity: domain.SeverityHigh, Status: domain.ThreatStatusActive,
		SHA256: ptr(strings.Repeat("a", 64)), FileSize: ptr(int64(0)), Description: ptr("Описание"),
		Tags: []string{"apt"}, FirstSeen: ptr(now.Add(-time.Hour)), LastSeen: ptr(now), CreatedAt: now, UpdatedAt: now,
	}
}
func ptr[T any](v T) *T { return &v }

func TestThreatHTTPResponses(t *testing.T) {
	databaseFailure := errors.New("password=private database detail")
	for _, tt := range []struct {
		name, method, path, body, serviceMethod string
		failure                                 error
		status                                  int
	}{
		{name: "create", method: "POST", path: "/info", body: `{"md5":"` + hash + `","name":"` + name + `"}`, serviceMethod: "create", status: 201},
		{name: "get", method: "GET", path: "/info/" + hash, serviceMethod: "get", status: 200},
		{name: "update", method: "PUT", path: "/info/" + hash, body: `{"name":"` + name + `"}`, serviceMethod: "update", status: 200},
		{name: "create validation", method: "POST", path: "/info", body: `{"md5":"` + hash + `","name":"` + name + `"}`, serviceMethod: "create", failure: errs.NewValidationError("last_seen is before first_seen"), status: 400},
		{name: "create duplicate", method: "POST", path: "/info", body: `{"md5":"` + hash + `","name":"` + name + `"}`, serviceMethod: "create", failure: fmt.Errorf("insert: %w", errs.ErrAlreadyExists), status: 409},
		{name: "create internal error", method: "POST", path: "/info", body: `{"md5":"` + hash + `","name":"` + name + `"}`, serviceMethod: "create", failure: databaseFailure, status: 500},
		{name: "get missing", method: "GET", path: "/info/" + hash, serviceMethod: "get", failure: fmt.Errorf("select: %w", errs.ErrNotFound), status: 404},
		{name: "get internal error", method: "GET", path: "/info/" + hash, serviceMethod: "get", failure: databaseFailure, status: 500},
		{name: "update validation", method: "PUT", path: "/info/" + hash, body: `{"name":"` + name + `"}`, serviceMethod: "update", failure: errs.NewValidationError("last_seen is before first_seen"), status: 400},
		{name: "update missing", method: "PUT", path: "/info/" + hash, body: `{"name":"` + name + `"}`, serviceMethod: "update", failure: errs.ErrNotFound, status: 404},
		{name: "update internal error", method: "PUT", path: "/info/" + hash, body: `{"name":"` + name + `"}`, serviceMethod: "update", failure: databaseFailure, status: 500},
	} {
		t.Run(tt.name, func(t *testing.T) {
			svc := &fakeService{result: fullThreat(), err: tt.failure}
			core, logs := observer.New(zap.DebugLevel)
			e, err := handlers.NewRouter(zap.New(core).Sugar(), v1.NewThreatHandler(svc))
			require.NoError(t, err)
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if tt.body != "" {
				req.Header.Set("Content-Type", "application/json")
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			require.Equal(t, tt.status, rec.Code, rec.Body.String())
			require.Equal(t, 1, svc.calls)
			require.Equal(t, tt.serviceMethod, svc.method)
			require.Equal(t, hash, svc.key)
			require.Contains(t, rec.Header().Get("Content-Type"), "application/json")
			if tt.failure == nil {
				var got api.ThreatResponse
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
				require.Equal(t, hash, got.Md5)
				require.Equal(t, name, got.Name)
				require.Equal(t, api.ThreatType("trojan"), got.Type)
				require.Equal(t, api.Platform("windows"), got.Platform)
				require.Equal(t, api.Severity("high"), got.Severity)
				require.Equal(t, api.ThreatStatus("active"), got.Status)
				require.Equal(t, svc.result.SHA256, got.Sha256)
				require.Equal(t, svc.result.FileSize, got.FileSize)
				require.Equal(t, svc.result.Description, got.Description)
				require.Equal(t, svc.result.Tags, got.Tags)
				require.Equal(t, svc.result.FirstSeen, got.FirstSeen)
				require.Equal(t, svc.result.LastSeen, got.LastSeen)
				require.Equal(t, svc.result.CreatedAt, got.CreatedAt)
				require.Equal(t, svc.result.UpdatedAt, got.UpdatedAt)
			} else {
				var got api.ErrorResponse
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
				require.NotNil(t, got.Message)
				require.NotEmpty(t, *got.Message)
				if tt.status == 500 {
					require.Nil(t, got.Details)
					require.NotContains(t, rec.Body.String(), "password")
					entries := logs.FilterMessage("Request failed").All()
					require.Len(t, entries, 1)
					require.Contains(t, fmt.Sprint(entries[0].ContextMap()["error"]), databaseFailure.Error())
				} else {
					require.NotNil(t, got.Details)
					require.Contains(t, *got.Details, tt.failure.Error())
				}
			}
		})
	}
}

func TestThreatInputMapping(t *testing.T) {
	full := fullThreat()
	input := domain.ThreatInput{
		Name: full.Name, Type: full.Type, Platform: full.Platform, Severity: full.Severity, Status: full.Status,
		SHA256: full.SHA256, FileSize: full.FileSize, Description: full.Description, Tags: full.Tags,
		FirstSeen: full.FirstSeen, LastSeen: full.LastSeen,
	}
	fields := map[string]any{
		"name": name, "type": "trojan", "platform": "windows", "severity": "high", "status": "active",
		"sha256": *full.SHA256, "file_size": 0, "description": *full.Description, "tags": full.Tags,
		"first_seen": full.FirstSeen, "last_seen": full.LastSeen,
	}
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			path := "/info/" + strings.ToUpper(hash)
			if method == http.MethodPost {
				fields["md5"] = strings.ToUpper(hash)
				path = "/info"
			} else {
				delete(fields, "md5")
			}
			body, err := json.Marshal(fields)
			require.NoError(t, err)
			svc := &fakeService{result: full}
			e, err := handlers.NewRouter(zap.NewNop().Sugar(), v1.NewThreatHandler(svc))
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req := httptest.NewRequest(method, path, strings.NewReader(string(body))).WithContext(ctx)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			require.Equal(t, 1, svc.calls, rec.Body.String())
			require.Equal(t, strings.ToUpper(hash), svc.key)
			require.Equal(t, input, svc.input)
			cancel()
			require.ErrorIs(t, svc.ctx.Err(), context.Canceled)
		})
	}
}

func TestThreatResponseOmitsUnknownValues(t *testing.T) {
	svc := &fakeService{result: domain.Threat{MD5: hash, Name: name, Type: domain.ThreatTypeUnknown,
		Platform: domain.PlatformUnknown, Severity: domain.SeverityUnknown, Status: domain.ThreatStatusActive}}
	e, err := handlers.NewRouter(zap.NewNop().Sugar(), v1.NewThreatHandler(svc))
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/info/"+hash, http.NoBody))
	require.Equal(t, 200, rec.Code)
	var body map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.JSONEq(t, "[]", string(body["tags"]))
	for _, key := range []string{"sha256", "file_size", "description", "first_seen", "last_seen"} {
		require.NotContains(t, body, key)
	}
}

func TestThreatHandlerMissingBody(t *testing.T) {
	svc := &fakeService{}
	h := v1.NewThreatHandler(svc)
	require.NotNil(t, h)
	_, err := h.CreateThreat(context.Background(), api.CreateThreatRequestObject{})
	require.ErrorIs(t, err, errs.ErrValidation)
	_, err = h.UpdateThreat(context.Background(), api.UpdateThreatRequestObject{Md5: hash})
	require.ErrorIs(t, err, errs.ErrValidation)
	require.Zero(t, svc.calls)
}
