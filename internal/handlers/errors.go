package handlers

import (
	"backend/internal/api"
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

const internalErrorMessage = "Internal server error"

// NewErrorHandler возвращает централизованный обработчик ошибок echo.
// Через него проходит любая ошибка: из хендлеров, middleware и роутера (404, 405).
// Клиентские ошибки (4xx) отдаются с деталями, всё остальное — 500 без деталей
func NewErrorHandler(lg *zap.SugaredLogger) echo.HTTPErrorHandler {
	return func(err error, c echo.Context) {
		// Ответ уже отправлен
		if c.Response().Committed {
			return
		}

		code, resp := toErrorResponse(err)
		if code >= http.StatusInternalServerError {
			lg.Errorw("Request failed",
				"method", c.Request().Method,
				"path", c.Request().URL.Path,
				"request_id", c.Response().Header().Get(echo.HeaderXRequestID),
				"error", err,
			)
		}

		var writeErr error
		if c.Request().Method == http.MethodHead {
			writeErr = c.NoContent(code)
		} else {
			writeErr = c.JSON(code, resp)
		}

		if writeErr != nil {
			lg.Errorw("Failed to write error response", "error", writeErr)
		}
	}
}

func toErrorResponse(err error) (int, api.ErrorResponse) {
	var he *echo.HTTPError
	if !errors.As(err, &he) || he.Code >= http.StatusInternalServerError {
		msg := internalErrorMessage
		return http.StatusInternalServerError, api.ErrorResponse{Message: &msg}
	}

	msg := http.StatusText(he.Code)
	resp := api.ErrorResponse{Message: &msg}

	// Дефолтные ошибки echo дублируют StatusText в Message — такие детали не нужны.
	if m, ok := he.Message.(string); ok && msg != m {
		resp.Details = &m
	}

	return he.Code, resp
}
