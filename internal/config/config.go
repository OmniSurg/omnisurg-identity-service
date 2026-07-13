// Package config defines the identity service configuration loaded from the
// environment via omnisurg-go-common/config.
package config

import (
	"encoding/base64"
	"fmt"

	common "github.com/OmniSurg/omnisurg-go-common/config"
)

// Config holds every tunable. Shared keys first, then service specific keys.
type Config struct {
	Env      string `envconfig:"OMNISURG_ENV" default:"local"`
	HTTPPort int    `envconfig:"OMNISURG_HTTP_PORT" default:"8081"`
	GRPCPort int    `envconfig:"OMNISURG_GRPC_PORT" default:"9081"`
	LogLevel string `envconfig:"OMNISURG_LOG_LEVEL" default:"info"`

	SentryDSN string `envconfig:"OMNISURG_SENTRY_DSN"`

	DatabaseURL string `envconfig:"OMNISURG_DATABASE_URL" required:"true"`

	JWTSecret     string `envconfig:"OMNISURG_JWT_SECRET" required:"true"`
	JWTTTLMinutes int    `envconfig:"OMNISURG_JWT_TTL_MINUTES" default:"60"`

	// InternalAPIKey guards future service-to-service /internal/* routes via
	// middleware.InternalAPIKey. No internal route is mounted in P1, so it is
	// optional; it becomes required when the first internal route is added.
	InternalAPIKey string `envconfig:"OMNISURG_INTERNAL_API_KEY"`

	KEKBase64 string `envconfig:"OMNISURG_KEK_BASE64" required:"true"`

	CORSOrigins []string `envconfig:"OMNISURG_CORS_ORIGINS" default:"http://localhost:5173"`
}

// Load reads the optional dotenv file then populates Config from the env.
func Load(dotenvPath string) (Config, error) {
	var cfg Config
	if err := common.Load(&cfg, dotenvPath); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// IsProduction reports whether this is the production environment.
func (c Config) IsProduction() bool { return c.Env == "production" }

// IsLocal reports whether this is the local environment.
func (c Config) IsLocal() bool { return c.Env == "local" }

// DecodeKEK base64 decodes the KEK and verifies it is exactly 32 bytes.
func (c Config) DecodeKEK() ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(c.KEKBase64)
	if err != nil {
		return nil, fmt.Errorf("config.DecodeKEK: base64 decode: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("config.DecodeKEK: KEK must be 32 bytes, got %d", len(raw))
	}
	return raw, nil
}
