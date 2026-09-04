package database

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type recordingPool struct {
	closed bool
}

func (p *recordingPool) Close() {
	p.closed = true
}

func TestMigrationEntries(t *testing.T) {
	t.Parallel()

	entries, err := migrationEntries()
	if err != nil {
		t.Fatalf("migrationEntries() error: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected at least one embedded migration")
	}
	for i := 1; i < len(entries); i++ {
		if entries[i-1].version >= entries[i].version {
			t.Fatalf("migrations not strictly ordered: %+v", entries)
		}
	}
}

func TestOpenInSchemaRejectsUnsafeNamesBeforeParsingOrConnecting(t *testing.T) {
	t.Parallel()
	for _, schema := range []string{"", "public,attacker", "MixedCase", "../public", strings.Repeat("a", 64)} {
		if _, err := OpenInSchema(context.Background(), "not a database URL", schema, 2); err == nil ||
			!strings.Contains(err.Error(), "schema name") {
			t.Fatalf("OpenInSchema(%q) error = %v, want schema-name rejection", schema, err)
		}
	}
}

func TestOpenPoolPairPartitionsOneConnectionBudget(t *testing.T) {
	t.Parallel()

	regularConfig, err := pgxpool.ParseConfig("postgres://latchway@database.example.test:5432/latchway?application_name=latchway")
	if err != nil {
		t.Fatalf("parse regular config: %v", err)
	}
	completionConfig, err := pgxpool.ParseConfig("postgres://latchway@database.example.test:5432/latchway?application_name=latchway")
	if err != nil {
		t.Fatalf("parse completion config: %v", err)
	}

	var observed []*pgxpool.Config
	opener := func(_ context.Context, cfg *pgxpool.Config) (*recordingPool, error) {
		observed = append(observed, cfg)
		return &recordingPool{}, nil
	}
	regular, completion, err := openPoolPair(
		context.Background(), regularConfig, completionConfig, 32, 8, opener,
	)
	if err != nil {
		t.Fatalf("openPoolPair() error: %v", err)
	}
	defer regular.Close()
	defer completion.Close()

	if len(observed) != 2 {
		t.Fatalf("opened %d pools, want 2", len(observed))
	}
	if observed[0] == observed[1] {
		t.Fatal("regular and completion pools reused one mutable configuration")
	}
	if got, want := observed[0].MaxConns, int32(24); got != want {
		t.Errorf("regular MaxConns = %d, want %d", got, want)
	}
	if got, want := observed[1].MaxConns, int32(8); got != want {
		t.Errorf("completion MaxConns = %d, want %d", got, want)
	}
	if got := observed[0].MaxConns + observed[1].MaxConns; got != 32 {
		t.Errorf("partitioned MaxConns sum = %d, want 32", got)
	}
	for index, cfg := range observed {
		if cfg.MinConns != 1 || cfg.MaxConnLifetime != 30*time.Minute ||
			cfg.MaxConnIdleTime != 5*time.Minute || cfg.HealthCheckPeriod != 30*time.Second {
			t.Errorf("pool %d does not have the standard bounded configuration: %+v", index, cfg)
		}
	}
	if regularConfig.ConnConfig.Host != completionConfig.ConnConfig.Host ||
		regularConfig.ConnConfig.Port != completionConfig.ConnConfig.Port ||
		regularConfig.ConnConfig.Database != completionConfig.ConnConfig.Database ||
		regularConfig.ConnConfig.User != completionConfig.ConnConfig.User ||
		regularConfig.ConnConfig.RuntimeParams["application_name"] != completionConfig.ConnConfig.RuntimeParams["application_name"] {
		t.Fatal("regular and completion pools did not preserve identical connection configuration")
	}
}

func TestOpenPoolPairClosesRegularPoolWhenCompletionOpenFails(t *testing.T) {
	t.Parallel()

	regularConfig, err := pgxpool.ParseConfig("postgres://localhost/latchway")
	if err != nil {
		t.Fatalf("parse regular config: %v", err)
	}
	completionConfig, err := pgxpool.ParseConfig("postgres://localhost/latchway")
	if err != nil {
		t.Fatalf("parse completion config: %v", err)
	}

	wantErr := errors.New("completion unavailable")
	regular := &recordingPool{}
	calls := 0
	opener := func(_ context.Context, _ *pgxpool.Config) (*recordingPool, error) {
		calls++
		if calls == 1 {
			return regular, nil
		}
		return nil, wantErr
	}
	gotRegular, gotCompletion, err := openPoolPair(
		context.Background(), regularConfig, completionConfig, 20, 5, opener,
	)
	if !errors.Is(err, wantErr) || !strings.Contains(err.Error(), "completion database pool") {
		t.Fatalf("openPoolPair() error = %v, want wrapped completion error", err)
	}
	if gotRegular != nil || gotCompletion != nil {
		t.Fatalf("failed pair = (%v, %v), want no returned pools", gotRegular, gotCompletion)
	}
	if !regular.closed {
		t.Fatal("regular pool remained open after completion pool failed")
	}
}

func TestOpenPartitionedRejectsInvalidBudgetBeforeParsing(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		total      int32
		completion int32
	}{
		{total: 1, completion: 1},
		{total: 2, completion: 0},
		{total: 2, completion: 2},
		{total: 20, completion: 21},
	} {
		if _, err := OpenPartitioned(context.Background(), "not a database URL", test.total, test.completion); err == nil ||
			!strings.Contains(err.Error(), "connections") {
			t.Errorf("OpenPartitioned(total=%d, completion=%d) error = %v, want partition rejection", test.total, test.completion, err)
		}
	}
}
