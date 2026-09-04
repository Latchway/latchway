package quota

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestStoreAdmissionConfigurationAndCancellation(t *testing.T) {
	t.Parallel()

	config, err := pgxpool.ParseConfig("postgres://quota:secret@127.0.0.1/latchway?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := NewStore(StoreConfig{Pool: pool, MaxConcurrentReservations: 5}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("oversized reservation admission error = %v", err)
	}
	store, err := NewStore(StoreConfig{Pool: pool, MaxConcurrentReservations: 1})
	if err != nil {
		t.Fatal(err)
	}
	release, err := acquireStoreAdmission(context.Background(), store.reservationAdmission)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := acquireStoreAdmission(ctx, store.reservationAdmission); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked admission error = %v", err)
	}
	release()
	canceled, cancelCanceled := context.WithCancel(context.Background())
	cancelCanceled()
	if _, err := acquireStoreAdmission(canceled, store.reservationAdmission); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled admission error = %v", err)
	}
	second, err := acquireStoreAdmission(context.Background(), store.reservationAdmission)
	if err != nil {
		t.Fatalf("canceled waiter leaked admission: %v", err)
	}
	second()
}

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
