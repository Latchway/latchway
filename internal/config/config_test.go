package config

import (
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	valid := Config{
		ListenAddress:    "0.0.0.0:8080",
		DatabaseURL:      "postgres://latchway:secret@localhost/latchway",
		Role:             RoleAll,
		LogLevel:         "info",
		MigrateOnStart:   true,
		ShutdownTimeout:  30 * time.Second,
		ReadTimeout:      15 * time.Second,
		IdleTimeout:      90 * time.Second,
		DBMaxConnections: 20,
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

func TestLoadRejectsMalformedEnvironment(t *testing.T) {
	t.Setenv("LATCHWAY_DATABASE_URL", "postgres://localhost/latchway")
	t.Setenv("LATCHWAY_MIGRATE_ON_START", "sometimes")
	if _, err := Load(); err == nil {
		t.Fatal("malformed boolean accepted")
	}
}
