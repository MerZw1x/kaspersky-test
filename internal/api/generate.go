package api

// Зависимости генератора изолированы в tools/oapi-codegen, чтобы обновление валидатора не ломало генерацию.
//go:generate go -C ../../tools/oapi-codegen tool oapi-codegen -config ../../api/oapi-codegen.yaml -o ../../internal/api/api.gen.go ../../api/openapi.yaml
