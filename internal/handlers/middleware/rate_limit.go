package middleware

import (
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"

	"backend/internal/config"
)

type client struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type RateLimiter struct {
	mu          sync.Mutex
	clients     map[string]*client
	cfg         config.RateLimitConfig
	now         func() time.Time
	lastCleanup time.Time
}

func NewRateLimiter(cfg config.RateLimitConfig, now func() time.Time) *RateLimiter {
	return &RateLimiter{clients: make(map[string]*client), cfg: cfg, now: now, lastCleanup: now()}
}

func (l *RateLimiter) Middleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !l.cfg.Enabled || c.Path() == "/health" {
			return next(c)
		}

		if !l.allow(c.RealIP()) {
			c.Response().Header().Set("Retry-After", "1")

			return echo.NewHTTPError(http.StatusTooManyRequests, "request rate limit exceeded")
		}

		return next(c)
	}
}

func (l *RateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	if now.Sub(l.lastCleanup) >= l.cfg.IdleTTL {
		for address, entry := range l.clients {
			if now.Sub(entry.lastSeen) >= l.cfg.IdleTTL {
				delete(l.clients, address)
			}
		}

		l.lastCleanup = now
	}

	entry, exists := l.clients[key]
	if !exists {
		// Ограничиваем память даже при большом числе уникальных адресов.
		if len(l.clients) >= l.cfg.MaxClients {
			return false
		}

		entry = &client{limiter: rate.NewLimiter(rate.Limit(l.cfg.RequestsPerSecond), l.cfg.Burst)}
		l.clients[key] = entry
	}

	entry.lastSeen = now

	return entry.limiter.AllowN(now, 1)
}
