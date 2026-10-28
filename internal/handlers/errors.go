package handlers

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

const internalErrorMessage = "Internal server error"

// ErrorResponse — тело ответа с ошибкой (components/schemas/ErrorResponse в спеке).
// Временный тип: на этапе кодогенерации заменится сгенерированным.
type ErrorResponse struct {
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

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

func toErrorResponse(err error) (int, ErrorResponse) {
	var he *echo.HTTPError
	if !errors.As(err, &he) || he.Code >= http.StatusInternalServerError {
		return http.StatusInternalServerError, ErrorResponse{Message: internalErrorMessage}
	}

	resp := ErrorResponse{Message: http.StatusText(he.Code)}

	// Дефолтные ошибки echo дублируют StatusText в Message — такие детали не нужны.
	if msg, ok := he.Message.(string); ok && msg != resp.Message {
		resp.Details = msg
	}

	return he.Code, resp
}
