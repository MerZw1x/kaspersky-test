package logger

import (
	"errors"
	"fmt"

	"go.uber.org/zap"

	"backend/internal/config"
)

// New создаёт логгер по конфигу: json — для Docker и сбора логов,
// console — человекочитаемый вывод для локальной разработки.
func New(cfg config.LogConfig) (*zap.SugaredLogger, error) {
	lvl, err := zap.ParseAtomicLevel(cfg.Level)
	if err != nil {
		return nil, fmt.Errorf("failed to parse log level: %w", err)
	}

	var zapCfg zap.Config

	// Уровень из пресета ниже перезаписывается значением из конфига.
	switch cfg.Format {
	case config.LogFormatJSON:
		zapCfg = zap.NewProductionConfig()
	case config.LogFormatConsole:
		zapCfg = zap.NewDevelopmentConfig()
	default:
		return nil, errors.New("log format must be json or console")
	}

	zapCfg.Level = lvl

	logger, err := zapCfg.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build logger: %w", err)
	}

	return logger.Sugar(), nil
}
