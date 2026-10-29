package middleware

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/labstack/echo/v4"

	"backend/internal/config"
)

func Authentication(cfg config.AuthConfig) openapi3filter.AuthenticationFunc {
	reader := sha256.Sum256([]byte(cfg.ReaderKey))
	writer := sha256.Sum256([]byte(cfg.WriterKey))

	return func(_ context.Context, input *openapi3filter.AuthenticationInput) error {
		if !cfg.Enabled {
			return nil
		}

		req := input.RequestValidationInput.Request

		keys := req.Header.Values("X-API-Key")
		if len(keys) != 1 || len(keys[0]) > 256 {
			return echo.NewHTTPError(http.StatusUnauthorized, "missing or invalid API key")
		}
		// Сравниваем хеши фиксированной длины и всегда проверяем обе роли.
		candidate := sha256.Sum256([]byte(keys[0]))
		isReader := subtle.ConstantTimeCompare(candidate[:], reader[:])

		isWriter := subtle.ConstantTimeCompare(candidate[:], writer[:])
		if isReader|isWriter == 0 {
			return echo.NewHTTPError(http.StatusUnauthorized, "missing or invalid API key")
		}

		if req.Method != http.MethodGet && isWriter == 0 {
			return echo.NewHTTPError(http.StatusForbidden, "writer role is required")
		}

		return nil
	}
}
