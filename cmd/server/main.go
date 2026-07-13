package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/OmniSurg/omnisurg-go-common/logger"
	mw "github.com/OmniSurg/omnisurg-go-common/middleware"
	pg "github.com/OmniSurg/omnisurg-go-common/postgres"
	"github.com/OmniSurg/omnisurg-identity-service/internal/config"
	"github.com/OmniSurg/omnisurg-identity-service/internal/grpcserver"
	"github.com/OmniSurg/omnisurg-identity-service/internal/handler"
	"github.com/OmniSurg/omnisurg-identity-service/internal/repository"
	"github.com/OmniSurg/omnisurg-identity-service/internal/security"
	"github.com/OmniSurg/omnisurg-identity-service/internal/service"
	identityv1 "github.com/OmniSurg/omnisurg-proto/gen/go/omnisurg/identity/v1"
	"github.com/getsentry/sentry-go"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(".env")
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	baseLogger := logger.New(logger.Options{
		Service:    "identity-service",
		Level:      level,
		Writer:     os.Stdout,
		Production: cfg.IsProduction(),
	})

	if cfg.SentryDSN != "" {
		if serr := sentry.Init(sentry.ClientOptions{Dsn: cfg.SentryDSN, Environment: cfg.Env}); serr != nil {
			baseLogger.Error().Err(serr).Msg("sentry init failed")
		} else {
			defer sentry.Flush(2 * time.Second)
		}
	}

	if merr := runMigrations(cfg.DatabaseURL); merr != nil {
		return fmt.Errorf("migrations: %w", merr)
	}

	ctx := context.Background()
	pool, err := pg.OpenPool(ctx, pg.Options{DSN: cfg.DatabaseURL})
	if err != nil {
		return fmt.Errorf("open pool: %w", err)
	}
	defer pool.Close()

	kek, err := cfg.DecodeKEK()
	if err != nil {
		return fmt.Errorf("decode kek: %w", err)
	}
	keyring, err := security.LoadKeyring(ctx, pool, kek)
	if err != nil {
		return fmt.Errorf("load keyring: %w", err)
	}

	userRepo := repository.NewUserRepository(pool, keyring)
	auditRepo := repository.NewAuditRepository(pool)
	idemRepo := repository.NewIdempotencyRepository(pool)

	ttl := time.Duration(cfg.JWTTTLMinutes) * time.Minute
	authSvc := service.NewAuthService(userRepo, auditRepo, keyring, cfg.JWTSecret, ttl)
	userSvc := service.NewUserService(userRepo, auditRepo, keyring)
	totpSvc := service.NewTotpService(userRepo, auditRepo, cfg.JWTSecret, ttl)

	router := handler.NewRouter(handler.RouterConfig{
		Auth:        authSvc,
		Users:       userSvc,
		Totp:        totpSvc,
		Idem:        idemRepo,
		Audit:       auditRepo,
		JWTSecret:   cfg.JWTSecret,
		Env:         cfg.Env,
		BaseLogger:  baseLogger,
		CORSOrigins: cfg.CORSOrigins,
		Ping:        pool.Ping,
	})

	httpSrv := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// The business server registers on the SAME grpc.Server as the health
	// server, behind the shared go-common interceptor (verifies the forwarded
	// JWT, propagates the request id, skips the health prefix). identity-service
	// is the user REGISTRY: a provider caller provisions the first practice_admin
	// for a NEW tenant cross tenant (the target tenant rides in the verified
	// JWT), so RequireTenant is false and per RPC tenant presence plus RBAC are
	// enforced in the adapter and service layer, mirroring the REST path. Login
	// stays REST only (it mints the JWT pre auth) and is intentionally absent
	// from the gRPC contract.
	grpcSrv := grpc.NewServer(
		grpc.UnaryInterceptor(mw.UnaryServerInterceptor(mw.InterceptorOptions{
			JWTSecret:     cfg.JWTSecret,
			RequireTenant: false,
		})),
	)
	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(grpcSrv, healthSrv)
	healthSrv.SetServingStatus("identity-service", healthpb.HealthCheckResponse_SERVING)

	identityv1.RegisterIdentityServiceServer(grpcSrv, grpcserver.New(userSvc))

	// Reflection eases gRPC smoke probes and local debugging. Disabled in
	// production, mirroring the non production only Swagger UI policy.
	if !cfg.IsProduction() {
		reflection.Register(grpcSrv)
	}

	errCh := make(chan error, 2)
	go func() {
		baseLogger.Info().Int("port", cfg.HTTPPort).Msg("http server listening")
		if serveErr := httpSrv.ListenAndServe(); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http serve: %w", serveErr)
		}
	}()
	go func() {
		lis, lerr := net.Listen("tcp", fmt.Sprintf(":%d", cfg.GRPCPort))
		if lerr != nil {
			errCh <- fmt.Errorf("grpc listen: %w", lerr)
			return
		}
		baseLogger.Info().Int("port", cfg.GRPCPort).Msg("grpc server listening (health plus identity)")
		if serveErr := grpcSrv.Serve(lis); serveErr != nil {
			errCh <- fmt.Errorf("grpc serve: %w", serveErr)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case sig := <-stop:
		baseLogger.Info().Str("signal", sig.String()).Msg("shutting down")
	case serveErr := <-errCh:
		return serveErr
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	grpcSrv.GracefulStop()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("http shutdown: %w", err)
	}
	return nil
}
