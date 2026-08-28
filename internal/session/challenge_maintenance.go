package session

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ChallengeMaintenance exposes only the bounded cleanup capability needed by
// worker replicas. It cannot create or consume challenges and therefore does
// not bypass the coordinator boundary.
type ChallengeMaintenance struct {
	store *ChallengeStore
}

func NewChallengeMaintenance(pool *pgxpool.Pool) (*ChallengeMaintenance, error) {
	if pool == nil {
		return nil, errors.New("challenge maintenance database pool is nil")
	}
	return &ChallengeMaintenance{store: &ChallengeStore{pool: pool, now: time.Now}}, nil
}

func (maintenance *ChallengeMaintenance) DeleteExpired(ctx context.Context, before time.Time, limit int) (int64, error) {
	if maintenance == nil || maintenance.store == nil {
		return 0, errors.New("challenge maintenance is unavailable")
	}
	return maintenance.store.DeleteExpired(ctx, before, limit)
}
