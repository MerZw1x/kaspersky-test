package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	echomiddleware "github.com/oapi-codegen/echo-middleware"
	"go.uber.org/zap"

	"backend/internal/api"
	"backend/internal/config"
	security "backend/internal/handlers/middleware"
)

const healthProbePath = "/health"

// health — проба живости для healthcheck в docker-compose.
func health(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
}

// recoverPanics превращает панику в ошибку со стеком и отдаёт её в NewErrorHandler:
// клиент получает 500, а стек попадает в zap, а не во встроенный логгер echo.
func recoverPanics() echo.MiddlewareFunc {
	return middleware.RecoverWithConfig(middleware.RecoverConfig{
		DisableStackAll: true, // стек только упавшей горутины
		LogErrorFunc: func(_ echo.Context, err error, stack []byte) error {
			return fmt.Errorf("panic recovered: %w\n%s", err, stack)
		},
	})
}

// requestLogger пишет по строке на запрос. Ошибку хендлера сразу отдаёт
// в NewErrorHandler (HandleError), чтобы в лог попал итоговый статус ответа.
// Подробности 5xx логирует сам NewErrorHandler, здесь только факт запроса.
func requestLogger(lg *zap.SugaredLogger) echo.MiddlewareFunc {
	return middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		Skipper: func(c echo.Context) bool {
			return c.Path() == healthProbePath
		},
		HandleError:  true,
		LogMethod:    true,
		LogURIPath:   true,
		LogStatus:    true,
		LogLatency:   true,
		LogRequestID: true,
		LogValuesFunc: func(_ echo.Context, v middleware.RequestLoggerValues) error {
			lg.Infow("Request",
				"method", v.Method,
				"path", v.URIPath,
				"status", v.Status,
				"latency", v.Latency,
				"request_id", v.RequestID,
			)

			return nil
		},
	})
}

type RouterOptions struct {
	Security config.SecurityConfig
	Now      func() time.Time
}

func NewRouter(lg *zap.SugaredLogger, strict api.StrictServerInterface, options ...RouterOptions) (*echo.Echo, error) {
	var opts RouterOptions

	if len(options) > 1 {
		return nil, errors.New("expected at most one RouterOptions")
	}

	if len(options) == 1 {
		opts = options[0]
	}

	if err := opts.Security.Validate(); err != nil {
		return nil, fmt.Errorf("invalid router security config: %w", err)
	}

	if opts.Now == nil {
		opts.Now = time.Now
	}

	e := echo.New()
	e.IPExtractor = echo.ExtractIPDirect() // Не доверяем подменяемым X-Forwarded-For и X-Real-IP.
	e.HideBanner = true
	e.HidePort = true
	e.HTTPErrorHandler = NewErrorHandler(lg)
	e.Pre(middleware.RemoveTrailingSlash())

	e.Use(
		middleware.RequestID(),
		requestLogger(lg),
		recoverPanics(),
		security.NewRateLimiter(opts.Security.RateLimit, opts.Now).Middleware,
		middleware.BodyLimit("64K"),
	)

	spec, err := api.GetSwagger()
	if err != nil {
		return nil, fmt.Errorf("get swagger: %w", err)
	}

	// Чтобы не вылетала ошибка при обращении к 127.0.0.1:8000 или по имени докер контейнера
	spec.Servers = nil

	e.Use(echomiddleware.OapiRequestValidatorWithOptions(spec, &echomiddleware.Options{
		Options: openapi3filter.Options{AuthenticationFunc: security.Authentication(opts.Security.Auth)},
		Skipper: func(c echo.Context) bool {
			return c.Path() == healthProbePath
		},
	}))

	api.RegisterHandlers(e, api.NewStrictHandler(strict, nil))

	e.GET(healthProbePath, health)

	return e, nil
}
