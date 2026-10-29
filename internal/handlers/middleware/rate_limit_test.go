package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/require"

	"backend/internal/config"
	security "backend/internal/handlers/middleware"
)

func TestRateLimitConcurrent(t *testing.T) {
	const burst = 5
	now := time.Now()
	limiter := security.NewRateLimiter(config.RateLimitConfig{
		Enabled: true, RequestsPerSecond: 1, Burst: burst, MaxClients: 10, IdleTTL: time.Minute,
	}, func() time.Time { return now })
	e := echo.New()
	e.IPExtractor = echo.ExtractIPDirect()
	e.Use(limiter.Middleware)
	e.GET("/", func(c echo.Context) error { return c.NoContent(http.StatusNoContent) })
	var allowed, blocked atomic.Int64
	var group sync.WaitGroup
	for range 100 {
		group.Go(func() {
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
			switch rec.Code {
			case 204:
				allowed.Add(1)
			case 429:
				blocked.Add(1)
			}
		})
	}
	group.Wait()
	require.EqualValues(t, burst, allowed.Load())
	require.EqualValues(t, 100-burst, blocked.Load())
}
