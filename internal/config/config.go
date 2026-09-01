// Package config loads and validates process configuration.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Role selects which process responsibilities are active.
type Role string

const (
	RoleAll    Role = "all"
	RoleAPI    Role = "api"
	RoleWorker Role = "worker"
)

// Config contains bootstrap configuration. Product policy is loaded from
// revisioned PostgreSQL configuration rather than environment variables.
type Config struct {
	ListenAddress        string
	DatabaseURL          string
	Role                 Role
	LogLevel             string
	MigrateOnStart       bool
	ShutdownTimeout      time.Duration
	ReadTimeout          time.Duration
	IdleTimeout          time.Duration
	DBMaxConnections     int32
	PublicOrigin         string
	AdminBootstrapToken  string
	AdminSessionLifetime time.Duration
}

// Load reads process configuration from environment variables.
func Load() (Config, error) {
	port := envOr("PORT", "8080")
	migrateOnStart, migrateErr := parseBoolEnv("LATCHWAY_MIGRATE_ON_START", true)
	shutdownTimeout, shutdownErr := parseDurationEnv("LATCHWAY_SHUTDOWN_TIMEOUT", 30*time.Second)
	readTimeout, readErr := parseDurationEnv("LATCHWAY_READ_TIMEOUT", 15*time.Second)
	idleTimeout, idleErr := parseDurationEnv("LATCHWAY_IDLE_TIMEOUT", 90*time.Second)
	maxConnections, maxConnectionsErr := parseIntEnv("LATCHWAY_DB_MAX_CONNECTIONS", 20)
	adminSessionLifetime, adminSessionErr := parseDurationEnv("LATCHWAY_ADMIN_SESSION_LIFETIME", 12*time.Hour)
	publicOrigin := envOr("LATCHWAY_PUBLIC_ORIGIN", "http://"+net.JoinHostPort("localhost", port))
	cfg := Config{
		ListenAddress:        envOr("LATCHWAY_LISTEN_ADDRESS", net.JoinHostPort("0.0.0.0", port)),
		DatabaseURL:          firstNonEmpty(os.Getenv("LATCHWAY_DATABASE_URL"), os.Getenv("DATABASE_URL")),
		Role:                 Role(envOr("LATCHWAY_ROLE", string(RoleAll))),
		LogLevel:             strings.ToLower(envOr("LATCHWAY_LOG_LEVEL", "info")),
		MigrateOnStart:       migrateOnStart,
		ShutdownTimeout:      shutdownTimeout,
		ReadTimeout:          readTimeout,
		IdleTimeout:          idleTimeout,
		DBMaxConnections:     int32(maxConnections),
		PublicOrigin:         publicOrigin,
		AdminBootstrapToken:  os.Getenv("LATCHWAY_ADMIN_BOOTSTRAP_TOKEN"),
		AdminSessionLifetime: adminSessionLifetime,
	}
	if err := errors.Join(migrateErr, shutdownErr, readErr, idleErr, maxConnectionsErr, adminSessionErr, cfg.Validate()); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate rejects unsafe or ambiguous bootstrap configuration.
func (c Config) Validate() error {
	var errs []error
	if strings.TrimSpace(c.DatabaseURL) == "" {
		errs = append(errs, errors.New("LATCHWAY_DATABASE_URL or DATABASE_URL is required"))
	}
	_, port, err := net.SplitHostPort(c.ListenAddress)
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid LATCHWAY_LISTEN_ADDRESS: %w", err))
	} else if parsedPort, parseErr := strconv.Atoi(port); parseErr != nil || parsedPort < 1 || parsedPort > 65535 {
		errs = append(errs, errors.New("listen address must use a numeric port between 1 and 65535"))
	}
	switch c.Role {
	case RoleAll, RoleAPI, RoleWorker:
	default:
		errs = append(errs, fmt.Errorf("invalid role %q: expected all, api, or worker", c.Role))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("invalid log level %q", c.LogLevel))
	}
	if c.ShutdownTimeout <= 0 {
		errs = append(errs, errors.New("shutdown timeout must be positive"))
	}
	if c.ReadTimeout <= 0 || c.IdleTimeout <= 0 {
		errs = append(errs, errors.New("HTTP timeouts must be positive"))
	}
	if c.DBMaxConnections < 2 || c.DBMaxConnections > 500 {
		errs = append(errs, errors.New("database max connections must be between 2 and 500"))
	}
	origin, originErr := url.Parse(c.PublicOrigin)
	if originErr != nil || origin.Scheme == "" || origin.Host == "" || origin.User != nil || origin.RawQuery != "" || origin.Fragment != "" || (origin.Path != "" && origin.Path != "/") {
		errs = append(errs, errors.New("LATCHWAY_PUBLIC_ORIGIN must be an absolute origin without credentials, path, query, or fragment"))
	} else if origin.Scheme != "https" && (origin.Scheme != "http" || !isLoopbackHost(origin.Hostname())) {
		errs = append(errs, errors.New("LATCHWAY_PUBLIC_ORIGIN must use HTTPS except on localhost or a loopback address"))
	}
	if c.AdminBootstrapToken != "" && (len(c.AdminBootstrapToken) < 32 || len(c.AdminBootstrapToken) > 2048) {
		errs = append(errs, errors.New("LATCHWAY_ADMIN_BOOTSTRAP_TOKEN must be between 32 and 2048 bytes"))
	}
	if c.AdminSessionLifetime < 5*time.Minute || c.AdminSessionLifetime > 30*24*time.Hour {
		errs = append(errs, errors.New("admin session lifetime must be between 5 minutes and 30 days"))
	}
	return errors.Join(errs...)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func parseBoolEnv(key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean: %w", key, err)
	}
	return parsed, nil
}

func parseDurationEnv(key string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be a duration: %w", key, err)
	}
	return parsed, nil
}

func parseIntEnv(key string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer: %w", key, err)
	}
	return parsed, nil
}
