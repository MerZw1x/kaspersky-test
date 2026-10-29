package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"backend/internal/domain"
	errs "backend/internal/errors"
	"backend/internal/service"
)

const md5 = "d41d8cd98f00b204e9800998ecf8427e"

type fakeRepository struct {
	create func(context.Context, domain.Threat) (domain.Threat, error)
	get    func(context.Context, string) (domain.Threat, error)
	update func(context.Context, domain.Threat) (domain.Threat, error)
}

func (r *fakeRepository) Create(ctx context.Context, threat domain.Threat) (domain.Threat, error) {
	return r.create(ctx, threat)
}
func (r *fakeRepository) GetByMD5(ctx context.Context, key string) (domain.Threat, error) {
	return r.get(ctx, key)
}
func (r *fakeRepository) Update(ctx context.Context, threat domain.Threat) (domain.Threat, error) {
	return r.update(ctx, threat)
}

func fixedNow() time.Time {
	return time.Date(2026, 10, 20, 12, 0, 0, 0, time.FixedZone("MSK", 3*60*60))
}
func ptr[T any](v T) *T { return &v }

func TestCreateDefaults(t *testing.T) {
	calls := 0
	clockCalls := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	repo := &fakeRepository{create: func(received context.Context, got domain.Threat) (domain.Threat, error) {
		calls++
		require.Equal(t, ctx, received)
		require.Equal(t, md5, got.MD5)
		require.Equal(t, "Trojan.Win32.Generic", got.Name)
		require.Equal(t, domain.ThreatTypeUnknown, got.Type)
		require.Equal(t, domain.PlatformUnknown, got.Platform)
		require.Equal(t, domain.SeverityUnknown, got.Severity)
		require.Equal(t, domain.ThreatStatusActive, got.Status)
		require.NotNil(t, got.Tags)
		require.Empty(t, got.Tags)
		require.Nil(t, got.SHA256)
		require.Nil(t, got.FileSize)
		require.Nil(t, got.Description)
		require.Nil(t, got.FirstSeen)
		require.Nil(t, got.LastSeen)
		require.Equal(t, fixedNow().UTC(), got.CreatedAt)
		require.Equal(t, got.CreatedAt, got.UpdatedAt)
		return got, nil
	}}
	svc := service.NewThreatService(repo, func() time.Time { clockCalls++; return fixedNow() })
	_, err := svc.Create(ctx, strings.ToUpper(md5), domain.ThreatInput{Name: "Trojan.Win32.Generic"})
	require.NoError(t, err)
	require.Equal(t, 1, calls)
	require.Equal(t, 1, clockCalls)
}

func TestCreateExplicitValuesAndInputOwnership(t *testing.T) {
	first := fixedNow().Add(-time.Hour)
	last := fixedNow()
	sha := strings.Repeat("A", 64)
	input := domain.ThreatInput{
		Name: "Trojan.Win32.Generic", Type: domain.ThreatTypeTrojan, Platform: domain.PlatformWindows,
		Severity: domain.SeverityHigh, Status: domain.ThreatStatusRevoked, SHA256: &sha,
		FileSize: ptr(int64(0)), Description: ptr("description"), Tags: []string{"apt"}, FirstSeen: &first, LastSeen: &last,
	}
	repo := &fakeRepository{create: func(_ context.Context, got domain.Threat) (domain.Threat, error) {
		require.Equal(t, input.Type, got.Type)
		require.Equal(t, input.Platform, got.Platform)
		require.Equal(t, input.Severity, got.Severity)
		require.Equal(t, input.Status, got.Status)
		require.Equal(t, strings.ToLower(sha), *got.SHA256)
		require.Zero(t, *got.FileSize)
		require.Equal(t, *input.Description, *got.Description)
		require.Equal(t, input.Tags, got.Tags)
		require.Equal(t, first.UTC(), *got.FirstSeen)
		require.Equal(t, last.UTC(), *got.LastSeen)
		*got.SHA256 = "changed"
		*got.FileSize = 42
		*got.Description = "changed"
		got.Tags[0] = "changed"
		*got.FirstSeen = time.Time{}
		*got.LastSeen = time.Time{}
		return got, nil
	}}
	_, err := service.NewThreatService(repo, fixedNow).Create(context.Background(), md5, input)
	require.NoError(t, err)
	require.Equal(t, strings.Repeat("A", 64), sha)
	require.Zero(t, *input.FileSize)
	require.Equal(t, "description", *input.Description)
	require.Equal(t, []string{"apt"}, input.Tags)
	require.Equal(t, fixedNow().Add(-time.Hour), first)
	require.Equal(t, fixedNow(), last)
}

func TestGetNormalizesMD5(t *testing.T) {
	want := domain.Threat{MD5: md5, Name: "Trojan.Win32.Generic"}
	repo := &fakeRepository{get: func(_ context.Context, key string) (domain.Threat, error) {
		require.Equal(t, md5, key)
		return want, nil
	}}
	got, err := service.NewThreatService(repo, fixedNow).GetByMD5(context.Background(), strings.ToUpper(md5))
	require.NoError(t, err)
	require.Equal(t, want, got)
}

func TestUpdateReplacesAndPreservesRepositoryResult(t *testing.T) {
	created := fixedNow().Add(-24 * time.Hour).UTC()
	repo := &fakeRepository{update: func(_ context.Context, got domain.Threat) (domain.Threat, error) {
		require.Equal(t, md5, got.MD5)
		require.Equal(t, "Backdoor.AndroidOS.Triada.a", got.Name)
		require.Equal(t, domain.ThreatTypeUnknown, got.Type)
		require.Equal(t, domain.PlatformUnknown, got.Platform)
		require.Equal(t, domain.SeverityUnknown, got.Severity)
		require.Equal(t, domain.ThreatStatusActive, got.Status)
		require.Nil(t, got.Description)
		require.Nil(t, got.SHA256)
		require.Nil(t, got.FileSize)
		require.Nil(t, got.FirstSeen)
		require.Nil(t, got.LastSeen)
		require.NotNil(t, got.Tags)
		require.Empty(t, got.Tags)
		require.True(t, got.CreatedAt.IsZero())
		require.Equal(t, fixedNow().UTC(), got.UpdatedAt)
		got.CreatedAt = created
		return got, nil
	}}
	got, err := service.NewThreatService(repo, fixedNow).Update(context.Background(), strings.ToUpper(md5), domain.ThreatInput{Name: "Backdoor.AndroidOS.Triada.a"})
	require.NoError(t, err)
	require.Equal(t, created, got.CreatedAt)
}

func TestInvalidMD5NeverReachesRepository(t *testing.T) {
	for _, key := range []string{"", "abc", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("g", 32), " " + md5, strings.Repeat("я", 16)} {
		t.Run(key, func(t *testing.T) {
			// Любой вызов незаданного метода фейка вызовет панику и провалит тест.
			svc := service.NewThreatService(&fakeRepository{}, fixedNow)
			_, err := svc.Create(context.Background(), key, domain.ThreatInput{})
			require.ErrorIs(t, err, errs.ErrValidation)
			_, err = svc.Update(context.Background(), key, domain.ThreatInput{})
			require.ErrorIs(t, err, errs.ErrValidation)
			_, err = svc.GetByMD5(context.Background(), key)
			require.ErrorIs(t, err, errs.ErrValidation)
		})
	}
}

func TestInputRules(t *testing.T) {
	past := fixedNow().Add(-time.Hour)
	now := fixedNow()
	future := now.Add(time.Nanosecond)
	tests := []struct {
		name         string
		input        domain.ThreatInput
		invalidField string
	}{
		{name: "reversed dates", input: domain.ThreatInput{FirstSeen: &now, LastSeen: &past}, invalidField: "last_seen"},
		{name: "future first", input: domain.ThreatInput{FirstSeen: &future}, invalidField: "first_seen"},
		{name: "future last", input: domain.ThreatInput{LastSeen: &future}, invalidField: "last_seen"},
		{name: "equal dates now", input: domain.ThreatInput{FirstSeen: &now, LastSeen: &now}},
		{name: "first only", input: domain.ThreatInput{FirstSeen: &past}},
		{name: "last only", input: domain.ThreatInput{LastSeen: &past}},
		{name: "chronological dates", input: domain.ThreatInput{FirstSeen: &past, LastSeen: &now}},
		{name: "bad type", input: domain.ThreatInput{Type: "invalid"}, invalidField: "type"},
		{name: "bad platform", input: domain.ThreatInput{Platform: "invalid"}, invalidField: "platform"},
		{name: "bad severity", input: domain.ThreatInput{Severity: "invalid"}, invalidField: "severity"},
		{name: "bad status", input: domain.ThreatInput{Status: "invalid"}, invalidField: "status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, method := range []string{"create", "update"} {
				t.Run(method, func(t *testing.T) {
					calls := 0
					save := func(_ context.Context, got domain.Threat) (domain.Threat, error) { calls++; return got, nil }
					svc := service.NewThreatService(&fakeRepository{create: save, update: save}, fixedNow)
					var err error
					if method == "create" {
						_, err = svc.Create(context.Background(), md5, tt.input)
					} else {
						_, err = svc.Update(context.Background(), md5, tt.input)
					}
					if tt.invalidField != "" {
						require.ErrorIs(t, err, errs.ErrValidation)
						require.Contains(t, err.Error(), tt.invalidField)
						require.Zero(t, calls)
					} else {
						require.NoError(t, err)
						require.Equal(t, 1, calls)
					}
				})
			}
		})
	}
}

func TestRepositoryErrorsPreserveIdentity(t *testing.T) {
	for _, failure := range []error{errs.ErrAlreadyExists, errs.ErrNotFound, errors.New("connection failed"), context.Canceled} {
		t.Run(failure.Error(), func(t *testing.T) {
			save := func(context.Context, domain.Threat) (domain.Threat, error) { return domain.Threat{}, failure }
			repo := &fakeRepository{create: save, update: save, get: func(context.Context, string) (domain.Threat, error) { return domain.Threat{}, failure }}
			svc := service.NewThreatService(repo, fixedNow)
			_, err := svc.Create(context.Background(), md5, domain.ThreatInput{})
			require.ErrorIs(t, err, failure)
			_, err = svc.Update(context.Background(), md5, domain.ThreatInput{})
			require.ErrorIs(t, err, failure)
			_, err = svc.GetByMD5(context.Background(), md5)
			require.ErrorIs(t, err, failure)
		})
	}
}
