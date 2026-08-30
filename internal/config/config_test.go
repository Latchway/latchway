package config

import (
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	valid := Config{
		ListenAddress:        "0.0.0.0:8080",
		DatabaseURL:          "postgres://latchway:secret@localhost/latchway",
		Role:                 RoleAll,
		LogLevel:             "info",
		MigrateOnStart:       true,
		ShutdownTimeout:      30 * time.Second,
		ReadTimeout:          15 * time.Second,
		IdleTimeout:          90 * time.Second,
		DBMaxConnections:     20,
		PublicOrigin:         "https://gateway.example.test",
		AdminSessionLifetime: 12 * time.Hour,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	invalid := valid
	invalid.DatabaseURL = ""
	invalid.Role = Role("mixed")
	invalid.DBMaxConnections = 1
	if err := invalid.Validate(); err == nil {
		t.Fatal("invalid config accepted")
	}
}

func TestValidateRejectsUnsafeAdministrativeOriginAndToken(t *testing.T) {
	t.Parallel()
	cfg := Config{
		ListenAddress: "127.0.0.1:8080", DatabaseURL: "postgres://localhost/latchway",
		Role: RoleAll, LogLevel: "info", ShutdownTimeout: time.Second,
		ReadTimeout: time.Second, IdleTimeout: time.Second, DBMaxConnections: 2,
		PublicOrigin: "http://gateway.example.test/path", AdminBootstrapToken: "short",
		AdminSessionLifetime: time.Minute,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("unsafe administrative configuration accepted")
	}
}

func TestLoadRejectsMalformedEnvironment(t *testing.T) {
	t.Setenv("LATCHWAY_DATABASE_URL", "postgres://localhost/latchway")
	t.Setenv("LATCHWAY_MIGRATE_ON_START", "sometimes")
	if _, err := Load(); err == nil {
		t.Fatal("malformed boolean accepted")
	}
}
