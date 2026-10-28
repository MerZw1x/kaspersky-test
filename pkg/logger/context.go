package logger

import (
	"context"

	"go.uber.org/zap"
)

type ctxKey struct{}

func CtxWithLogger(parent context.Context, logger *zap.SugaredLogger) context.Context {
	return context.WithValue(parent, ctxKey{}, logger)
}

func GetLoggerFromCtx(ctx context.Context) *zap.SugaredLogger {
	if l, ok := ctx.Value(ctxKey{}).(*zap.SugaredLogger); ok {
		return l
	}

	return zap.NewNop().Sugar()
}
