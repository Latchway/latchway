package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	valid := Config{
		ListenAddress:           "0.0.0.0:8080",
		DatabaseURL:             "postgres://latchway:secret@localhost/latchway",
		Role:                    RoleAll,
		LogLevel:                "info",
		MigrateOnStart:          true,
		ShutdownTimeout:         30 * time.Second,
		ReadTimeout:             15 * time.Second,
		IdleTimeout:             90 * time.Second,
		DBMaxConnections:        20,
		DBCompletionConnections: 5,
		PublicOrigin:            "https://gateway.example.test",
		AdminSessionLifetime:    12 * time.Hour,
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
		DBCompletionConnections: 1,
		PublicOrigin:            "http://gateway.example.test/path", AdminBootstrapToken: "short",
		AdminSessionLifetime: time.Minute,
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("unsafe administrative configuration accepted")
	}
}

func TestValidateRejectsBootstrapTokenBeyondContractLimit(t *testing.T) {
	t.Parallel()
	cfg := Config{
		ListenAddress: "127.0.0.1:8080", DatabaseURL: "postgres://localhost/latchway",
		Role: RoleAll, LogLevel: "info", ShutdownTimeout: time.Second,
		ReadTimeout: time.Second, IdleTimeout: time.Second, DBMaxConnections: 2,
		DBCompletionConnections: 1,
		PublicOrigin:            "http://127.0.0.1:8080", AdminBootstrapToken: strings.Repeat("x", 2049),
		AdminSessionLifetime: time.Hour,
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "32 and 2048 bytes") {
		t.Fatalf("overlong bootstrap token error = %v", err)
	}
}

func TestLoadRejectsMalformedEnvironment(t *testing.T) {
	t.Setenv("LATCHWAY_DATABASE_URL", "postgres://localhost/latchway")
	t.Setenv("LATCHWAY_MIGRATE_ON_START", "sometimes")
	if _, err := Load(); err == nil {
		t.Fatal("malformed boolean accepted")
	}
}

func TestDefaultDBCompletionConnections(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		total        int
		wantRegular  int
		wantComplete int
	}{
		{total: 2, wantRegular: 1, wantComplete: 1},
		{total: 3, wantRegular: 2, wantComplete: 1},
		{total: 20, wantRegular: 15, wantComplete: 5},
		{total: 32, wantRegular: 24, wantComplete: 8},
	} {
		completion := defaultDBCompletionConnections(test.total)
		if completion != test.wantComplete {
			t.Errorf("defaultDBCompletionConnections(%d) = %d, want %d", test.total, completion, test.wantComplete)
		}
		if regular := test.total - completion; regular != test.wantRegular {
			t.Errorf("regular connections for total %d = %d, want %d", test.total, regular, test.wantRegular)
		}
	}
}

func TestLoadDerivesAndOverridesCompletionConnections(t *testing.T) {
	t.Setenv("LATCHWAY_DATABASE_URL", "postgres://localhost/latchway")
	t.Setenv("LATCHWAY_DB_MAX_CONNECTIONS", "32")
	t.Setenv("LATCHWAY_DB_COMPLETION_CONNECTIONS", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if cfg.DBCompletionConnections != 8 {
		t.Fatalf("default completion connections = %d, want 8", cfg.DBCompletionConnections)
	}

	t.Setenv("LATCHWAY_DB_COMPLETION_CONNECTIONS", "6")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load() with override error: %v", err)
	}
	if cfg.DBCompletionConnections != 6 {
		t.Fatalf("overridden completion connections = %d, want 6", cfg.DBCompletionConnections)
	}
}

func TestLoadRejectsMalformedCompletionConnections(t *testing.T) {
	t.Setenv("LATCHWAY_DATABASE_URL", "postgres://localhost/latchway")
	t.Setenv("LATCHWAY_DB_COMPLETION_CONNECTIONS", "several")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "LATCHWAY_DB_COMPLETION_CONNECTIONS") {
		t.Fatalf("malformed completion connections error = %v, want named environment rejection", err)
	}
}

func TestLoadRejectsConnectionIntegersOutsideInt32(t *testing.T) {
	for _, key := range []string{"LATCHWAY_DB_MAX_CONNECTIONS", "LATCHWAY_DB_COMPLETION_CONNECTIONS"} {
		t.Run(key, func(t *testing.T) {
			t.Setenv("LATCHWAY_DATABASE_URL", "postgres://localhost/latchway")
			t.Setenv(key, "4294967316")

			if _, err := Load(); err == nil || !strings.Contains(err.Error(), key+" must be an integer") {
				t.Fatalf("out-of-range %s error = %v, want named integer rejection", key, err)
			}
		})
	}
}

func TestValidateRejectsUnsafeCompletionPartition(t *testing.T) {
	t.Parallel()

	valid := Config{
		ListenAddress: "127.0.0.1:8080", DatabaseURL: "postgres://localhost/latchway",
		Role: RoleAll, LogLevel: "info", ShutdownTimeout: time.Second,
		ReadTimeout: time.Second, IdleTimeout: time.Second, DBMaxConnections: 20,
		DBCompletionConnections: 5, PublicOrigin: "http://127.0.0.1:8080",
		AdminSessionLifetime: time.Hour,
	}
	for _, completionConnections := range []int32{0, -1, 20, 21} {
		cfg := valid
		cfg.DBCompletionConnections = completionConnections
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "completion connections") {
			t.Errorf("completion connections %d error = %v, want partition rejection", completionConnections, err)
		}
	}
}
