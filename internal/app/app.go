// Package app собирает зависимости сервиса и управляет его жизненным циклом:
// запуск HTTP-сервера, ожидание сигнала остановки, graceful shutdown.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"

	"backend/internal/config"
	"backend/internal/handlers"
	"backend/pkg/logger"
)

// App — собранное приложение, готовое к запуску через Run.
type App struct {
	cfg     *config.Config
	logger  *zap.SugaredLogger
	e       *echo.Echo
	closers []io.Closer
}

// New читает конфиг и собирает все зависимости. Не завершает процесс сам
func New(configPaths ...string) (*App, error) {
	cfg, err := config.ReadConfig(configPaths...)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}

	lg, err := logger.New(cfg.Log)
	if err != nil {
		return nil, fmt.Errorf("create logger: %w", err)
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.HTTPErrorHandler = handlers.NewErrorHandler(lg)
	e.Pre(middleware.RemoveTrailingSlash())

	// echo сам создаёт http.Server и при Start не трогает таймауты,
	// поэтому выставляем их заранее.
	e.Server.ReadHeaderTimeout = cfg.HTTPServer.ReadHeaderTimeout
	e.Server.ReadTimeout = cfg.HTTPServer.ReadTimeout
	e.Server.WriteTimeout = cfg.HTTPServer.WriteTimeout
	e.Server.IdleTimeout = cfg.HTTPServer.IdleTimeout

	handlers.Register(e, lg)

	return &App{
		cfg:    cfg,
		logger: lg,
		e:      e,
	}, nil
}

// Run запускает HTTP-сервер и блокируется до SIGINT/SIGTERM или падения
// сервера, после чего выполняет graceful shutdown.
func (a *App) Run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Буфер 1: горутина сможет записать ошибку и завершиться,
	// даже если Run уже вышел из select по сигналу.
	errCh := make(chan error, 1)

	go func() {
		a.logger.Infof("Starting HTTP server on %s", a.cfg.HTTPServer.Listen)

		errCh <- a.e.Start(a.cfg.HTTPServer.Listen)
	}()

	var runErr error

	select {
	case <-ctx.Done():
		// Возвращаем дефолтную обработку сигналов: повторный Ctrl+C
		// во время shutdown убьёт процесс сразу.
		stop()
		a.logger.Info("Shutdown signal received")
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = fmt.Errorf("http server: %w", err)
		}
	}

	return errors.Join(runErr, a.shutdown())
}

// shutdown даёт начатым запросам GracefulTimeout на завершение,
// затем освобождает ресурсы.
func (a *App) shutdown() error {
	ctx, cancel := context.WithTimeout(context.Background(), a.cfg.GracefulTimeout)
	defer cancel()

	var errs []error

	if err := a.e.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("shutdown http server: %w", err))

		// Не уложились в таймаут — рвём оставшиеся соединения принудительно.
		if errors.Is(err, context.DeadlineExceeded) {
			_ = a.e.Close()
		}
	}

	for i := len(a.closers) - 1; i >= 0; i-- {
		if err := a.closers[i].Close(); err != nil {
			errs = append(errs, fmt.Errorf("close resource: %w", err))
		}
	}

	a.logger.Info("Application stopped")

	// Sync для stdout на macOS всегда возвращает ошибку — игнорируем.
	_ = a.logger.Sync()

	return errors.Join(errs...)
}
