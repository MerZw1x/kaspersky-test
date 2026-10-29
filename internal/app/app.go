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
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"backend/internal/config"
	"backend/internal/handlers"
	v1 "backend/internal/handlers/v1"
	"backend/internal/repository/postgres"
	"backend/internal/service"
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

	tlsConfig, err := serverTLSConfig(cfg.HTTPServer.TLS)
	if err != nil {
		return nil, err
	}

	lg, err := logger.New(cfg.Log)
	if err != nil {
		return nil, fmt.Errorf("create logger: %w", err)
	}

	db, err := initDB(cfg.Database)
	if err != nil {
		_ = lg.Sync()
		return nil, fmt.Errorf("initialize database: %w", err)
	}

	repo := postgres.NewThreatRepository(db)
	threatService := service.NewThreatService(repo, time.Now)
	threatHandler := v1.NewThreatHandler(threatService)

	e, err := handlers.NewRouter(lg, threatHandler, handlers.RouterOptions{Security: cfg.Security})
	if err != nil {
		_ = db.Close()
		_ = lg.Sync()

		return nil, fmt.Errorf("create router: %w", err)
	}

	// echo сам создаёт http.Server и при Start не трогает таймауты,
	// поэтому выставляем их заранее.
	e.Server.Addr = cfg.HTTPServer.Listen
	e.Server.TLSConfig = tlsConfig
	e.Server.ReadHeaderTimeout = cfg.HTTPServer.ReadHeaderTimeout
	e.Server.ReadTimeout = cfg.HTTPServer.ReadTimeout
	e.Server.WriteTimeout = cfg.HTTPServer.WriteTimeout
	e.Server.IdleTimeout = cfg.HTTPServer.IdleTimeout

	return &App{
		cfg:     cfg,
		logger:  lg,
		e:       e,
		closers: []io.Closer{db},
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

		errCh <- a.e.StartServer(a.e.Server)
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
