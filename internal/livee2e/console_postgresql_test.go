package livee2e_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/app"
	"github.com/latchway/latchway/internal/config"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/telemetry"
)

const liveE2EEnableEnvironment = "LATCHWAY_CONSOLE_LIVE_E2E"

func TestConsoleFirstRunAgainstLiveStack(t *testing.T) {
	if os.Getenv(liveE2EEnableEnvironment) != "1" {
		t.Skip(liveE2EEnableEnvironment + "=1 is required")
	}
	databaseURL := strings.TrimSpace(os.Getenv("LATCHWAY_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Fatal("LATCHWAY_TEST_DATABASE_URL is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	adminPool, err := database.Open(ctx, databaseURL, 2)
	if err != nil {
		t.Fatalf("open PostgreSQL administration connection: %v", err)
	}

	schema := "console_live_" + randomHex(t, 8)
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		t.Fatalf("create isolated PostgreSQL schema: %v", err)
	}
	serverExited := false
	var serverExit <-chan error
	t.Cleanup(func() {
		defer adminPool.Close()
		cancel()
		if !serverExited && serverExit != nil {
			select {
			case runErr := <-serverExit:
				if runErr != nil {
					t.Errorf("stop live gateway: %v", runErr)
				}
			case <-time.After(10 * time.Second):
				t.Error("live gateway did not stop within ten seconds")
			}
		}
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dropCancel()
		if _, dropErr := adminPool.Exec(
			dropCtx, "DROP SCHEMA "+pgx.Identifier{schema}.Sanitize()+" CASCADE",
		); dropErr != nil {
			t.Errorf("drop isolated PostgreSQL schema: %v", dropErr)
		}
	})

	scopedDatabaseURL := databaseURLForSchema(t, databaseURL, schema)
	listenAddress := availableLoopbackAddress(t)
	publicOrigin := "http://" + listenAddress
	masterKey := randomStandardBase64(t, 32)
	bootstrapToken := "bootstrap_" + randomBase64(t, 32)
	ownerPassword := "LiveE2E-" + randomBase64(t, 24)
	providerCredential := "provider_" + randomBase64(t, 32)
	t.Setenv(secrets.MasterKeyEnvironment, masterKey)
	t.Setenv("OTEL_TRACES_EXPORTER", "none")
	t.Setenv("OTEL_SDK_DISABLED", "false")

	runCtx, stopServer := context.WithCancel(ctx)
	exit := make(chan error, 1)
	serverExit = exit
	go func() {
		exit <- app.Run(runCtx, config.Config{
			ListenAddress: listenAddress, DatabaseURL: scopedDatabaseURL,
			Role: config.RoleAll, LogLevel: "error", MigrateOnStart: true,
			ShutdownTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
			IdleTimeout: 30 * time.Second, DBMaxConnections: 8,
			PublicOrigin: publicOrigin, AdminBootstrapToken: bootstrapToken,
			AdminSessionLifetime: time.Hour,
		}, telemetry.NewLogger(io.Discard, "error"))
	}()
	defer stopServer()

	if runErr := waitForReady(ctx, publicOrigin, exit); runErr != nil {
		serverExited = true
		t.Fatalf("start live gateway: %v", runErr)
	}

	consoleDirectory := repositoryConsoleDirectory(t)
	command := exec.CommandContext(
		ctx, "pnpm", "exec", "playwright", "test", "e2e/live-stack.spec.ts", "--project=chromium",
	)
	command.Dir = consoleDirectory
	command.Env = append(os.Environ(),
		"LATCHWAY_CONSOLE_LIVE_E2E_BASE_URL="+publicOrigin,
		"LATCHWAY_CONSOLE_LIVE_E2E_BOOTSTRAP_TOKEN="+bootstrapToken,
		"LATCHWAY_CONSOLE_LIVE_E2E_OWNER_PASSWORD="+ownerPassword,
		"LATCHWAY_CONSOLE_LIVE_E2E_PROVIDER_CREDENTIAL="+providerCredential,
	)
	output, commandErr := command.CombinedOutput()
	if commandErr != nil {
		t.Fatalf("run browser against live gateway: %v\n%s", commandErr, safeOutput(output, bootstrapToken, ownerPassword, providerCredential, masterKey))
	}

	stopServer()
	select {
	case runErr := <-exit:
		serverExited = true
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			t.Fatalf("live gateway shutdown: %v", runErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("live gateway did not drain within ten seconds")
	}
}

func waitForReady(ctx context.Context, origin string, exit <-chan error) error {
	client := &http.Client{Timeout: time.Second}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	lastReadiness := "no response"
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, origin+"/readyz", nil)
		if err != nil {
			return err
		}
		response, requestErr := client.Do(request)
		if requestErr == nil {
			body, _ := io.ReadAll(io.LimitReader(response.Body, 4<<10))
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return nil
			}
			lastReadiness = fmt.Sprintf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
		} else {
			lastReadiness = requestErr.Error()
		}
		select {
		case runErr := <-exit:
			if runErr == nil {
				return errors.New("gateway stopped before readiness")
			}
			return runErr
		case <-ctx.Done():
			return fmt.Errorf("%w (last readiness result: %s)", ctx.Err(), lastReadiness)
		case <-ticker.C:
		}
	}
}

func databaseURLForSchema(t *testing.T, raw, schema string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse PostgreSQL URL: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func availableLoopbackAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve loopback address: %v", err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release loopback address: %v", err)
	}
	return address
}

func repositoryConsoleDirectory(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve live E2E source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "web", "console"))
}

func randomHex(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generate isolated schema suffix: %v", err)
	}
	return hex.EncodeToString(value)
}

func randomBase64(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generate ephemeral live E2E credential: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func randomStandardBase64(t *testing.T, size int) string {
	t.Helper()
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		t.Fatalf("generate ephemeral live E2E master key: %v", err)
	}
	return base64.StdEncoding.EncodeToString(value)
}

func safeOutput(output []byte, secretsToRemove ...string) string {
	replacements := make([]string, 0, len(secretsToRemove)*2)
	for _, secret := range secretsToRemove {
		if secret != "" {
			replacements = append(replacements, secret, "[REDACTED]")
		}
	}
	redacted := strings.NewReplacer(replacements...).Replace(string(output))
	const maximum = 64 << 10
	if len(redacted) > maximum {
		redacted = redacted[len(redacted)-maximum:]
	}
	return redacted
}
