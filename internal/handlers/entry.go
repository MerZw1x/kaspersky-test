package handlers

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
)

const healthProbePath = "/health"

// Register подключает middleware и маршруты к echo.
//
// Порядок middleware важен: RequestID ставится первым, чтобы id попал в лог,
// а Recover — последним, чтобы паника в хендлере превратилась в 500
// до того, как логгер запишет статус ответа.
func Register(e *echo.Echo, lg *zap.SugaredLogger) {
	e.Use(
		middleware.RequestID(),
		requestLogger(lg),
		recoverPanics(),
	)

	e.GET(healthProbePath, health)
}

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
