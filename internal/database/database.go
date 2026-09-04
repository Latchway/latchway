// Package database owns PostgreSQL connectivity and schema migrations.
package database

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/migrations"
)

const migrationLockID int64 = 0x4c41544348574159

var isolatedSchemaName = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// Pools contains independent regular-work and request-completion pools. The
// caller owns Pools and must call Close when both pools are no longer in use;
// components receiving either pool as a dependency must not close it.
type Pools struct {
	Regular    *pgxpool.Pool
	Completion *pgxpool.Pool
}

// Close closes both pools.
func (p *Pools) Close() {
	if p == nil {
		return
	}
	if p.Completion != nil {
		p.Completion.Close()
	}
	if p.Regular != nil {
		p.Regular.Close()
	}
}

// Open constructs and verifies a bounded PostgreSQL pool.
func Open(ctx context.Context, databaseURL string, maxConnections int32) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database configuration: %w", err)
	}
	return openConfig(ctx, cfg, maxConnections)
}

// OpenPartitioned constructs and verifies two independently bounded pools from
// the same PostgreSQL configuration. maxConnections remains the process-wide
// connection budget; completionConnections is reserved from that budget and
// the remainder is assigned to regular work.
func OpenPartitioned(ctx context.Context, databaseURL string, maxConnections, completionConnections int32) (*Pools, error) {
	if err := validatePartition(maxConnections, completionConnections); err != nil {
		return nil, err
	}
	regularConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database configuration: %w", err)
	}
	completionConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database configuration: %w", err)
	}

	regular, completion, err := openPoolPair(
		ctx,
		regularConfig,
		completionConfig,
		maxConnections,
		completionConnections,
		openConfiguredPool,
	)
	if err != nil {
		return nil, err
	}
	return &Pools{Regular: regular, Completion: completion}, nil
}

// OpenInSchema constructs a pool whose every connection is confined to one
// explicitly named PostgreSQL schema. It is used by destructive verification
// and migration drills so they cannot accidentally resolve objects from the
// operator's application schema through a connection-pool reuse.
func OpenInSchema(ctx context.Context, databaseURL, schema string, maxConnections int32) (*pgxpool.Pool, error) {
	if !isolatedSchemaName.MatchString(schema) {
		return nil, errors.New("isolated database schema name is invalid")
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database configuration: %w", err)
	}
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = make(map[string]string)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	return openConfig(ctx, cfg, maxConnections)
}

func openConfig(ctx context.Context, cfg *pgxpool.Config, maxConnections int32) (*pgxpool.Pool, error) {
	if err := configurePool(cfg, maxConnections); err != nil {
		return nil, err
	}
	return openConfiguredPool(ctx, cfg)
}

func configurePool(cfg *pgxpool.Config, maxConnections int32) error {
	if cfg == nil || maxConnections < 1 {
		return errors.New("database pool configuration is invalid")
	}
	cfg.MaxConns = maxConnections
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second
	return nil
}

func openConfiguredPool(ctx context.Context, cfg *pgxpool.Config) (*pgxpool.Pool, error) {
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	return pool, nil
}

type closeablePool interface {
	Close()
}

type configuredPoolOpener[T closeablePool] func(context.Context, *pgxpool.Config) (T, error)

func openPoolPair[T closeablePool](
	ctx context.Context,
	regularConfig, completionConfig *pgxpool.Config,
	maxConnections, completionConnections int32,
	opener configuredPoolOpener[T],
) (T, T, error) {
	var zero T
	if err := validatePartition(maxConnections, completionConnections); err != nil {
		return zero, zero, err
	}
	if opener == nil {
		return zero, zero, errors.New("database pool opener is invalid")
	}
	if err := configurePool(regularConfig, maxConnections-completionConnections); err != nil {
		return zero, zero, err
	}
	if err := configurePool(completionConfig, completionConnections); err != nil {
		return zero, zero, err
	}

	regular, err := opener(ctx, regularConfig)
	if err != nil {
		return zero, zero, fmt.Errorf("open regular database pool: %w", err)
	}
	completion, err := opener(ctx, completionConfig)
	if err != nil {
		regular.Close()
		return zero, zero, fmt.Errorf("open completion database pool: %w", err)
	}
	return regular, completion, nil
}

func validatePartition(maxConnections, completionConnections int32) error {
	if maxConnections < 2 {
		return errors.New("database max connections must allow two pools")
	}
	if completionConnections < 1 || completionConnections >= maxConnections {
		return errors.New("database completion connections must be at least 1 and less than database max connections")
	}
	return nil
}

// Migrator applies embedded forward-only migrations under a session-scoped
// PostgreSQL advisory lock.
type Migrator struct {
	pool *pgxpool.Pool
}

// NewMigrator creates a migrator for pool.
func NewMigrator(pool *pgxpool.Pool) *Migrator {
	return &Migrator{pool: pool}
}

// Up applies every pending migration in version order.
func (m *Migrator) Up(ctx context.Context) error {
	conn, err := m.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrationLockID); err != nil {
		return fmt.Errorf("acquire migration lock: %w", err)
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_, _ = conn.Exec(unlockCtx, "SELECT pg_advisory_unlock($1)", migrationLockID)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version bigint PRIMARY KEY,
			name text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	entries, err := migrationEntries()
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := m.apply(ctx, conn.Conn(), entry); err != nil {
			return err
		}
	}
	return nil
}

// Status returns the current and available schema versions.
func (m *Migrator) Status(ctx context.Context) (current, available int64, err error) {
	entries, err := migrationEntries()
	if err != nil {
		return 0, 0, err
	}
	if len(entries) > 0 {
		available = entries[len(entries)-1].version
	}
	if err := m.pool.QueryRow(ctx, "SELECT COALESCE(max(version), 0) FROM schema_migrations").Scan(&current); err != nil {
		if isUndefinedTable(err) {
			return 0, available, nil
		}
		return 0, available, fmt.Errorf("read migration status: %w", err)
	}
	return current, available, nil
}

func (m *Migrator) apply(ctx context.Context, conn *pgx.Conn, entry migrationEntry) error {
	var applied bool
	if err := conn.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = $1)", entry.version).Scan(&applied); err != nil {
		return fmt.Errorf("check migration %s: %w", entry.name, err)
	}
	if applied {
		return nil
	}

	contents, err := fs.ReadFile(migrations.Files, entry.name)
	if err != nil {
		return fmt.Errorf("read migration %s: %w", entry.name, err)
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin migration %s: %w", entry.name, err)
	}
	defer func() {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer cancel()
		_ = tx.Rollback(rollbackCtx)
	}()

	if _, err := tx.Exec(ctx, string(contents)); err != nil {
		return fmt.Errorf("execute migration %s: %w", entry.name, err)
	}
	if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version, name) VALUES ($1, $2)", entry.version, entry.name); err != nil {
		return fmt.Errorf("record migration %s: %w", entry.name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit migration %s: %w", entry.name, err)
	}
	return nil
}

type migrationEntry struct {
	version int64
	name    string
}

func migrationEntries() ([]migrationEntry, error) {
	names, err := fs.Glob(migrations.Files, "*.sql")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	entries := make([]migrationEntry, 0, len(names))
	for _, name := range names {
		prefix, _, ok := strings.Cut(filepath.Base(name), "_")
		if !ok {
			return nil, fmt.Errorf("migration %q has no numeric prefix", name)
		}
		version, err := strconv.ParseInt(prefix, 10, 64)
		if err != nil || version <= 0 {
			return nil, fmt.Errorf("migration %q has invalid version", name)
		}
		entries = append(entries, migrationEntry{version: version, name: name})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].version < entries[j].version })
	for i := 1; i < len(entries); i++ {
		if entries[i-1].version == entries[i].version {
			return nil, fmt.Errorf("duplicate migration version %d", entries[i].version)
		}
	}
	return entries, nil
}

func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}
