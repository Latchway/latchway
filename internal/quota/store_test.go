package quota

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPersistenceFailureIsClassifiableAndSanitized(t *testing.T) {
	t.Parallel()
	config, err := pgxpool.ParseConfig("postgres://quota:secret@127.0.0.1/latchway?sslmode=disable")
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatalf("create pool: %v", err)
	}
	pool.Close()
	store, err := NewStore(StoreConfig{Pool: pool})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	_, err = store.Reserve(context.Background(), validReserveInput(t))
	if !errors.Is(err, ErrDependency) {
		t.Fatalf("closed persistence returned %v, want ErrDependency", err)
	}
	for _, secret := range []string{"secret", "127.0.0.1", "closed pool"} {
		if strings.Contains(strings.ToLower(err.Error()), secret) {
			t.Fatalf("dependency error leaked %q: %v", secret, err)
		}
	}

	invalid := validReserveInput(t)
	invalid.Rules = nil
	_, err = store.Reserve(context.Background(), invalid)
	if !errors.Is(err, ErrInvalidInput) || errors.Is(err, ErrDependency) {
		t.Fatalf("invalid input classification = %v", err)
	}
}
