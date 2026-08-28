package attestation

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/id"
)

var appAttestPostgreSQLSchemaPattern = regexp.MustCompile(`\Alatchway_app_attest_[0-9]+\z`)

func TestPostgreSQLAppAttestKeyStoreRoundTripsExactStateAndCopies(t *testing.T) {
	fixture := newPostgreSQLAppAttestFixture(t)
	originalPublicKey := append([]byte(nil), fixture.state.PublicKeyX963...)
	callbackOutput := cloneAppAttestStoredKey(fixture.state)
	if err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		current AppAttestStoredKey,
		exists bool,
	) (AppAttestStoredKey, error) {
		if exists || len(current.PublicKeyX963) != 0 {
			t.Fatalf("new credential callback current=%#v exists=%v", current, exists)
		}
		return callbackOutput, nil
	}); err != nil {
		t.Fatalf("register App Attest key: %v", err)
	}
	for index := range callbackOutput.PublicKeyX963 {
		callbackOutput.PublicKeyX963[index] ^= 0xff
	}

	first := snapshotPostgreSQLAppAttestKey(t, fixture)
	if !bytes.Equal(first.PublicKeyX963, originalPublicKey) ||
		first.ApplicationID != fixture.state.ApplicationID ||
		first.EnvironmentID != fixture.state.EnvironmentID ||
		first.Platform != fixture.state.Platform ||
		first.PrincipalID != fixture.state.PrincipalID ||
		first.DPoPJKT != fixture.state.DPoPJKT ||
		first.AttestationEnvironment != fixture.state.AttestationEnvironment ||
		first.AppIDHash != fixture.state.AppIDHash ||
		first.Counter != 0 || !first.ExtensionsPresent ||
		first.ValidationCategory != fixture.state.ValidationCategory ||
		first.BundleVersion != fixture.state.BundleVersion ||
		!first.AttestedAt.Equal(fixture.state.AttestedAt) {
		t.Fatalf("stored state does not round-trip exactly: %#v", first)
	}

	// The callback owns its snapshot. Mutating it before returning an error must
	// neither change the row nor poison a later callback.
	errStop := errors.New("stop after owned snapshot")
	err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		current AppAttestStoredKey,
		exists bool,
	) (AppAttestStoredKey, error) {
		if !exists {
			t.Fatal("registered key disappeared")
		}
		current.PublicKeyX963[1] ^= 0xff
		return current, errStop
	})
	if !errors.Is(err, errStop) {
		t.Fatalf("callback error = %v, want owned error", err)
	}
	if afterMutation := snapshotPostgreSQLAppAttestKey(t, fixture); !bytes.Equal(afterMutation.PublicKeyX963, originalPublicKey) {
		t.Fatal("callback mutation escaped the defensive input boundary")
	}

	if err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		current AppAttestStoredKey,
		exists bool,
	) (AppAttestStoredKey, error) {
		if !exists {
			t.Fatal("registered key disappeared before counter update")
		}
		current.Counter = 7
		current.LastAssertionHash = sha256.Sum256([]byte("round-trip assertion seven"))
		current.ExtensionsPresent = false
		current.ValidationCategory = 0
		current.BundleVersion = ""
		return current, nil
	}); err != nil {
		t.Fatalf("consume serialized assertion counter: %v", err)
	}
	updated := snapshotPostgreSQLAppAttestKey(t, fixture)
	if updated.Counter != 7 || updated.LastAssertionHash == ([sha256.Size]byte{}) ||
		updated.ExtensionsPresent || updated.ValidationCategory != 0 || updated.BundleVersion != "" {
		t.Fatalf("updated mutable state = %#v", updated)
	}

	var installationID *string
	var providerKeyID string
	var providerKeyHash []byte
	var lastAssertionHash []byte
	var attestedSeconds int64
	var attestedNanosecond int32
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT installation_id, provider_key_id, provider_key_hash, last_assertion_hash,
		       attested_at_unix_seconds, attested_at_nanosecond
		FROM attestation_keys
		WHERE provider = 'app_attest' AND provider_key_hash = $1
	`, fixture.keyID[:]).Scan(
		&installationID, &providerKeyID, &providerKeyHash, &lastAssertionHash,
		&attestedSeconds, &attestedNanosecond,
	); err != nil {
		t.Fatalf("inspect persisted key row: %v", err)
	}
	if installationID != nil || providerKeyID != base64.StdEncoding.EncodeToString(fixture.keyID[:]) ||
		!bytes.Equal(providerKeyHash, fixture.keyID[:]) ||
		!bytes.Equal(lastAssertionHash, updated.LastAssertionHash[:]) ||
		attestedSeconds != fixture.state.AttestedAt.Unix() ||
		attestedNanosecond != int32(fixture.state.AttestedAt.Nanosecond()) {
		t.Fatalf("unexpected exact persistence columns: installation=%v provider=%q seconds=%d nanos=%d",
			installationID, providerKeyID, attestedSeconds, attestedNanosecond)
	}

	err = fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		current AppAttestStoredKey,
		_ bool,
	) (AppAttestStoredKey, error) {
		current.Counter++
		current.DPoPJKT = appAttestPostgreSQLThumbprint("other immutable key")
		return current, nil
	})
	if !errors.Is(err, ErrAppAttestKeyStore) {
		t.Fatalf("immutable scope mutation error = %v, want store failure", err)
	}
	if current := snapshotPostgreSQLAppAttestKey(t, fixture); current.Counter != 7 || current.DPoPJKT != fixture.state.DPoPJKT {
		t.Fatalf("immutable mutation changed state: %#v", current)
	}
}

func TestPostgreSQLAppAttestKeyStoreExactExistingStateIsIdempotent(t *testing.T) {
	fixture := newPostgreSQLAppAttestFixture(t)
	if err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		_ AppAttestStoredKey,
		exists bool,
	) (AppAttestStoredKey, error) {
		if exists {
			t.Fatal("fresh idempotency fixture unexpectedly exists")
		}
		return cloneAppAttestStoredKey(fixture.state), nil
	}); err != nil {
		t.Fatalf("register idempotency fixture: %v", err)
	}
	beforeVersion, beforeUpdatedAt := postgreSQLAppAttestRowVersion(t, fixture)

	callbackCalls := 0
	if err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		current AppAttestStoredKey,
		exists bool,
	) (AppAttestStoredKey, error) {
		callbackCalls++
		if !exists || !sameAppAttestImmutableState(current, fixture.state) ||
			!sameAppAttestMutableState(current, fixture.state) {
			t.Fatalf("idempotent callback state=%#v exists=%v", current, exists)
		}
		return current, nil
	}); err != nil || callbackCalls != 1 {
		t.Fatalf("exact existing-state replay err=%v callbacks=%d", err, callbackCalls)
	}
	afterVersion, afterUpdatedAt := postgreSQLAppAttestRowVersion(t, fixture)
	if afterVersion != beforeVersion || !afterUpdatedAt.Equal(beforeUpdatedAt) {
		t.Fatalf("exact replay wrote key row: version %q -> %q updated %v -> %v",
			beforeVersion, afterVersion, beforeUpdatedAt, afterUpdatedAt)
	}
	assertPostgreSQLAppAttestReceiptCount(t, fixture, 0)

	err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		current AppAttestStoredKey,
		_ bool,
	) (AppAttestStoredKey, error) {
		current.BundleVersion = "1.0.217"
		return current, nil
	})
	if !errors.Is(err, ErrAppAttestKeyStore) {
		t.Fatalf("same-counter metadata mutation err=%v, want store failure", err)
	}

	if err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		current AppAttestStoredKey,
		_ bool,
	) (AppAttestStoredKey, error) {
		current.Counter = 2
		current.LastAssertionHash = sha256.Sum256([]byte("idempotency assertion two"))
		return current, nil
	}); err != nil {
		t.Fatalf("advance idempotency fixture counter: %v", err)
	}
	assertionVersion, assertionUpdatedAt := postgreSQLAppAttestRowVersion(t, fixture)
	if err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		current AppAttestStoredKey,
		_ bool,
	) (AppAttestStoredKey, error) {
		return current, nil
	}); err != nil {
		t.Fatalf("exact persisted assertion retry: %v", err)
	}
	retryVersion, retryUpdatedAt := postgreSQLAppAttestRowVersion(t, fixture)
	if retryVersion != assertionVersion || !retryUpdatedAt.Equal(assertionUpdatedAt) {
		t.Fatalf("exact assertion retry wrote key row: version %q -> %q updated %v -> %v",
			assertionVersion, retryVersion, assertionUpdatedAt, retryUpdatedAt)
	}
	err = fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		current AppAttestStoredKey,
		_ bool,
	) (AppAttestStoredKey, error) {
		current.LastAssertionHash = sha256.Sum256([]byte("different equal-counter assertion"))
		return current, nil
	})
	if !errors.Is(err, ErrAppAttestKeyStore) {
		t.Fatalf("same-counter assertion digest mutation err=%v, want store failure", err)
	}
	err = fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		current AppAttestStoredKey,
		_ bool,
	) (AppAttestStoredKey, error) {
		current.Counter = 1
		return current, nil
	})
	if !errors.Is(err, ErrAppAttestKeyStore) {
		t.Fatalf("counter decrease err=%v, want store failure", err)
	}
	if current := snapshotPostgreSQLAppAttestKey(t, fixture); current.Counter != 2 ||
		current.BundleVersion != fixture.state.BundleVersion {
		t.Fatalf("rejected replay mutation changed state: %#v", current)
	}
}

func TestPostgreSQLAppAttestKeyStoreSeparatesAppleEnvironmentFromBindingSlug(t *testing.T) {
	fixture := newPostgreSQLAppAttestFixture(t)
	if _, err := fixture.pool.Exec(fixture.ctx, `
		UPDATE environments
		SET slug = 'staging', kind = 'staging'
		WHERE organization_id = $1 AND application_id = $2 AND environment_id = $3
	`, fixture.organizationID, fixture.applicationID, fixture.environmentID); err != nil {
		t.Fatalf("change fixture binding environment: %v", err)
	}
	fixture.state.EnvironmentID = "staging"
	fixture.state.AttestationEnvironment = AppAttestDevelopment
	if err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		_ AppAttestStoredKey,
		exists bool,
	) (AppAttestStoredKey, error) {
		if exists {
			t.Fatal("fresh development credential unexpectedly exists")
		}
		return cloneAppAttestStoredKey(fixture.state), nil
	}); err != nil {
		t.Fatalf("register development key in staging binding: %v", err)
	}

	var appleEnvironment, bindingEnvironment string
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT environment, binding_environment
		FROM attestation_keys
		WHERE provider = 'app_attest' AND provider_key_hash = $1
	`, fixture.keyID[:]).Scan(&appleEnvironment, &bindingEnvironment); err != nil {
		t.Fatalf("read separated environments: %v", err)
	}
	if appleEnvironment != string(AppAttestDevelopment) || bindingEnvironment != "staging" {
		t.Fatalf("Apple/binding environments = %q/%q, want development/staging",
			appleEnvironment, bindingEnvironment)
	}
	loaded := snapshotPostgreSQLAppAttestKey(t, fixture)
	if loaded.AttestationEnvironment != AppAttestDevelopment || loaded.EnvironmentID != "staging" {
		t.Fatalf("loaded separated environment state = %#v", loaded)
	}
}

func TestPostgreSQLAppAttestKeyStoreSerializesConcurrentRegistrationAndCounters(t *testing.T) {
	fixture := newPostgreSQLAppAttestFixture(t)
	const registrars = 12
	registeredElsewhere := errors.New("registered by another transaction")
	results := make(chan error, registrars)
	var callbackCalls atomic.Int32
	var wait sync.WaitGroup
	for index := 0; index < registrars; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			store, err := NewPostgreSQLAppAttestKeyStore(fixture.pool)
			if err != nil {
				results <- err
				return
			}
			results <- store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
				_ AppAttestStoredKey,
				exists bool,
			) (AppAttestStoredKey, error) {
				callbackCalls.Add(1)
				if exists {
					return AppAttestStoredKey{}, registeredElsewhere
				}
				return cloneAppAttestStoredKey(fixture.state), nil
			})
		}()
	}
	wait.Wait()
	close(results)
	succeeded := 0
	conflicted := 0
	for err := range results {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, registeredElsewhere):
			conflicted++
		default:
			t.Fatalf("concurrent registration error: %v", err)
		}
	}
	if succeeded != 1 || conflicted != registrars-1 || callbackCalls.Load() != registrars {
		t.Fatalf("registration results success=%d conflict=%d callbacks=%d",
			succeeded, conflicted, callbackCalls.Load())
	}

	const assertions = 24
	observedCounters := make(chan int, assertions)
	results = make(chan error, assertions)
	for index := 0; index < assertions; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			store, err := NewPostgreSQLAppAttestKeyStore(fixture.pool)
			if err != nil {
				results <- err
				return
			}
			results <- store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
				current AppAttestStoredKey,
				exists bool,
			) (AppAttestStoredKey, error) {
				if !exists {
					return AppAttestStoredKey{}, errors.New("serialized key disappeared")
				}
				observedCounters <- int(current.Counter)
				current.Counter++
				current.LastAssertionHash = sha256.Sum256([]byte(fmt.Sprintf(
					"serialized assertion %d", current.Counter,
				)))
				return current, nil
			})
		}()
	}
	wait.Wait()
	close(results)
	close(observedCounters)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent counter transaction: %v", err)
		}
	}
	counters := make([]int, 0, assertions)
	for counter := range observedCounters {
		counters = append(counters, counter)
	}
	sort.Ints(counters)
	for index, counter := range counters {
		if counter != index {
			t.Fatalf("serialized callback counters=%v", counters)
		}
	}
	if current := snapshotPostgreSQLAppAttestKey(t, fixture); current.Counter != assertions {
		t.Fatalf("final counter=%d want=%d", current.Counter, assertions)
	}
}

func TestPostgreSQLAppAttestKeyStoreCancellationBoundary(t *testing.T) {
	fixture := newPostgreSQLAppAttestFixture(t)
	ctx, cancel := context.WithCancel(fixture.ctx)
	err := fixture.store.TransactAppAttestKey(ctx, fixture.keyID, func(
		_ AppAttestStoredKey,
		_ bool,
	) (AppAttestStoredKey, error) {
		cancel()
		return cloneAppAttestStoredKey(fixture.state), nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("precommit cancellation error = %v, want context.Canceled", err)
	}
	assertPostgreSQLAppAttestKeyCount(t, fixture, 0)
	assertPostgreSQLAppAttestReceiptCount(t, fixture, 0)

	ctx, cancel = context.WithCancel(fixture.ctx)
	store := *fixture.store
	store.commit = func(commitCtx context.Context, tx pgx.Tx) error {
		cancel()
		return tx.Commit(commitCtx)
	}
	err = store.TransactAppAttestKey(ctx, fixture.keyID, func(
		_ AppAttestStoredKey,
		exists bool,
	) (AppAttestStoredKey, error) {
		if exists {
			t.Fatal("canceled registration unexpectedly persisted")
		}
		return cloneAppAttestStoredKey(fixture.state), nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation immediately before COMMIT error = %v, want context.Canceled", err)
	}
	assertPostgreSQLAppAttestKeyCount(t, fixture, 0)
	assertPostgreSQLAppAttestReceiptCount(t, fixture, 0)

	ctx, cancel = context.WithCancel(fixture.ctx)
	store = *fixture.store
	store.commit = func(commitCtx context.Context, tx pgx.Tx) error {
		err := tx.Commit(commitCtx)
		cancel()
		return err
	}
	err = store.TransactAppAttestKey(ctx, fixture.keyID, func(
		_ AppAttestStoredKey,
		exists bool,
	) (AppAttestStoredKey, error) {
		if exists {
			t.Fatal("canceled registration unexpectedly persisted")
		}
		return cloneAppAttestStoredKey(fixture.state), nil
	})
	if err != nil || !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("postcommit cancellation result err=%v context=%v", err, ctx.Err())
	}
	assertPostgreSQLAppAttestKeyCount(t, fixture, 1)
	assertPostgreSQLAppAttestReceiptCount(t, fixture, 0)
}

func TestPostgreSQLAppAttestKeyStoreResolvesLostCommitAcknowledgement(t *testing.T) {
	fixture := newPostgreSQLAppAttestFixture(t)
	store := *fixture.store
	leakingDetail := "commit acknowledgement lost at sensitive-postgres.example.test"
	store.commit = func(commitCtx context.Context, tx pgx.Tx) error {
		if err := tx.Commit(commitCtx); err != nil {
			return err
		}
		return errors.New(leakingDetail)
	}
	callbackCalls := 0
	err := store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		_ AppAttestStoredKey,
		exists bool,
	) (AppAttestStoredKey, error) {
		callbackCalls++
		if exists {
			t.Fatal("fresh ambiguous-commit key unexpectedly exists")
		}
		return cloneAppAttestStoredKey(fixture.state), nil
	})
	if err != nil || callbackCalls != 1 {
		t.Fatalf("resolved ambiguous commit err=%v callbacks=%d", err, callbackCalls)
	}
	assertPostgreSQLAppAttestKeyCount(t, fixture, 1)
	assertPostgreSQLAppAttestReceiptCount(t, fixture, 0)
}

func TestPostgreSQLAppAttestCommitResolutionWaitsForOriginalKeyTransaction(t *testing.T) {
	fixture := newPostgreSQLAppAttestFixture(t)
	if err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		_ AppAttestStoredKey,
		_ bool,
	) (AppAttestStoredKey, error) {
		return cloneAppAttestStoredKey(fixture.state), nil
	}); err != nil {
		t.Fatalf("register receipt-resolution key: %v", err)
	}

	commitToken := sha256.Sum256([]byte("in-flight App Attest commit receipt"))
	original, err := fixture.pool.BeginTx(fixture.ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin simulated in-flight transaction: %v", err)
	}
	t.Cleanup(func() { rollbackAppAttestKeyTransaction(original) })
	if _, err := original.Exec(
		fixture.ctx, "SELECT pg_advisory_xact_lock($1)", appAttestAdvisoryLockID(fixture.keyID),
	); err != nil {
		t.Fatalf("lock simulated in-flight key: %v", err)
	}
	if err := recordPostgreSQLAppAttestCommitReceipt(
		fixture.ctx, original, fixture.keyID, commitToken, fixture.state.Counter,
	); err != nil {
		t.Fatalf("write simulated uncommitted receipt: %v", err)
	}

	type resolution struct {
		committed bool
		err       error
	}
	resolved := make(chan resolution, 1)
	go func() {
		committed, resolveErr := fixture.store.hasAppAttestCommitReceipt(
			fixture.ctx, fixture.keyID, commitToken,
		)
		resolved <- resolution{committed: committed, err: resolveErr}
	}()
	select {
	case early := <-resolved:
		t.Fatalf("receipt resolution returned before original transaction ended: %#v", early)
	case <-time.After(100 * time.Millisecond):
	}
	if err := original.Commit(fixture.ctx); err != nil {
		t.Fatalf("commit simulated in-flight transaction: %v", err)
	}
	select {
	case result := <-resolved:
		if result.err != nil || !result.committed {
			t.Fatalf("resolved in-flight receipt = %#v", result)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("receipt resolution did not continue after original transaction committed")
	}
	fixture.store.deleteAppAttestCommitReceipt(fixture.ctx, commitToken)
	assertPostgreSQLAppAttestReceiptCount(t, fixture, 0)
}

func TestPostgreSQLAppAttestKeyStoreCommitFailureIsRedactedAndRollsBack(t *testing.T) {
	fixture := newPostgreSQLAppAttestFixture(t)
	store := *fixture.store
	leakingDetail := "commit failed at sensitive-postgres.example.test"
	store.commit = func(context.Context, pgx.Tx) error {
		return errors.New(leakingDetail)
	}
	err := store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		_ AppAttestStoredKey,
		exists bool,
	) (AppAttestStoredKey, error) {
		if exists {
			t.Fatal("fresh commit-failure key unexpectedly exists")
		}
		return cloneAppAttestStoredKey(fixture.state), nil
	})
	if !errors.Is(err, ErrAppAttestKeyStore) || strings.Contains(err.Error(), leakingDetail) {
		t.Fatalf("commit failure = %v, want redacted store sentinel", err)
	}
	assertPostgreSQLAppAttestKeyCount(t, fixture, 0)
	assertPostgreSQLAppAttestReceiptCount(t, fixture, 0)
}

func TestPostgreSQLAppAttestKeyStoreFailsClosedOnCorruptOrRevokedRows(t *testing.T) {
	for _, test := range []struct {
		name               string
		mutate             string
		bypassLifecycleSQL bool
		args               func(postgreSQLAppAttestFixture) []any
	}{
		{
			name:               "credential text disagrees with binary identifier",
			mutate:             "UPDATE attestation_keys SET provider_key_id = $2 WHERE provider_key_hash = $1",
			bypassLifecycleSQL: true,
			args: func(fixture postgreSQLAppAttestFixture) []any {
				other := sha256.Sum256([]byte("different credential identifier"))
				return []any{fixture.keyID[:], base64.StdEncoding.EncodeToString(other[:])}
			},
		},
		{
			name:               "public key is not the credential key",
			mutate:             "UPDATE attestation_keys SET public_key = $2 WHERE provider_key_hash = $1",
			bypassLifecycleSQL: true,
			args: func(fixture postgreSQLAppAttestFixture) []any {
				otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					t.Fatalf("generate corruption key: %v", err)
				}
				return []any{fixture.keyID[:], elliptic.Marshal(elliptic.P256(), otherKey.X, otherKey.Y)}
			},
		},
		{
			name:   "key lifecycle is invalid",
			mutate: "UPDATE attestation_keys SET status = 'invalid' WHERE provider_key_hash = $1",
			args: func(fixture postgreSQLAppAttestFixture) []any {
				return []any{fixture.keyID[:]}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newPostgreSQLAppAttestFixture(t)
			if err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
				_ AppAttestStoredKey,
				_ bool,
			) (AppAttestStoredKey, error) {
				return cloneAppAttestStoredKey(fixture.state), nil
			}); err != nil {
				t.Fatalf("register key: %v", err)
			}
			if test.bypassLifecycleSQL {
				if _, err := fixture.pool.Exec(fixture.ctx, `
					ALTER TABLE attestation_keys DISABLE TRIGGER attestation_keys_lifecycle_guard
				`); err != nil {
					t.Fatalf("disable lifecycle trigger for physical-corruption simulation: %v", err)
				}
				t.Cleanup(func() {
					_, _ = fixture.pool.Exec(context.Background(), `
						ALTER TABLE attestation_keys ENABLE TRIGGER attestation_keys_lifecycle_guard
					`)
				})
			}
			if _, err := fixture.pool.Exec(fixture.ctx, test.mutate, test.args(fixture)...); err != nil {
				t.Fatalf("corrupt stored row: %v", err)
			}
			if test.bypassLifecycleSQL {
				if _, err := fixture.pool.Exec(fixture.ctx, `
					ALTER TABLE attestation_keys ENABLE TRIGGER attestation_keys_lifecycle_guard
				`); err != nil {
					t.Fatalf("restore lifecycle trigger after corruption simulation: %v", err)
				}
			}
			callbackCalls := 0
			err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
				current AppAttestStoredKey,
				exists bool,
			) (AppAttestStoredKey, error) {
				callbackCalls++
				if !exists {
					t.Fatal("corrupt row was presented as a new credential")
				}
				current.Counter++
				return current, nil
			})
			if !errors.Is(err, ErrAppAttestKeyStore) || callbackCalls != 1 {
				t.Fatalf("corrupt row result err=%v callbacks=%d", err, callbackCalls)
			}
			var counter int64
			if err := fixture.pool.QueryRow(fixture.ctx, `
				SELECT sign_count FROM attestation_keys WHERE provider_key_hash = $1
			`, fixture.keyID[:]).Scan(&counter); err != nil || counter != 0 {
				t.Fatalf("corrupt row counter=%d err=%v", counter, err)
			}
		})
	}
}

func TestPostgreSQLAppAttestKeyStoreRejectsInvalidConstructionAndOutput(t *testing.T) {
	if _, err := NewPostgreSQLAppAttestKeyStore(nil); !errors.Is(err, ErrAppAttestKeyStore) {
		t.Fatalf("nil pool constructor error = %v", err)
	}
	fixture := newPostgreSQLAppAttestFixture(t)
	if err := fixture.store.TransactAppAttestKey(nil, fixture.keyID, func(
		AppAttestStoredKey,
		bool,
	) (AppAttestStoredKey, error) {
		return AppAttestStoredKey{}, nil
	}); !errors.Is(err, ErrAppAttestKeyStore) {
		t.Fatalf("nil context error = %v", err)
	}
	invalid := cloneAppAttestStoredKey(fixture.state)
	invalid.PublicKeyX963 = append([]byte(nil), invalid.PublicKeyX963[:64]...)
	if err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		AppAttestStoredKey,
		bool,
	) (AppAttestStoredKey, error) {
		return invalid, nil
	}); !errors.Is(err, ErrAppAttestKeyStore) {
		t.Fatalf("invalid callback output error = %v", err)
	}
	assertPostgreSQLAppAttestKeyCount(t, fixture, 0)
}

func TestPostgreSQLAppAttestCleanupIsBoundedAndSkipsLockedRows(t *testing.T) {
	fixture := newPostgreSQLAppAttestFixture(t)
	var cleanupNow time.Time
	if err := fixture.pool.QueryRow(fixture.ctx, "SELECT transaction_timestamp()").Scan(&cleanupNow); err != nil {
		t.Fatalf("read cleanup database time: %v", err)
	}
	cleanupNow = cleanupNow.UTC()
	oldOrphan, _ := insertPostgreSQLAppAttestCleanupKey(
		t, fixture, cleanupNow.Add(-48*time.Hour), false,
	)
	oldWithReceipt, oldWithReceiptID := insertPostgreSQLAppAttestCleanupKey(
		t, fixture, cleanupNow.Add(-48*time.Hour), false,
	)
	linkedOld, _ := insertPostgreSQLAppAttestCleanupKey(
		t, fixture, cleanupNow.Add(-48*time.Hour), true,
	)
	recent, recentID := insertPostgreSQLAppAttestCleanupKey(
		t, fixture, cleanupNow.Add(-time.Hour), false,
	)

	lockedExpiredToken := sha256.Sum256([]byte("locked expired App Attest receipt"))
	otherExpiredToken := sha256.Sum256([]byte("other expired App Attest receipt"))
	liveToken := sha256.Sum256([]byte("live App Attest receipt"))
	insertPostgreSQLAppAttestCleanupReceipt(
		t, fixture, recentID, lockedExpiredToken,
		cleanupNow.Add(-4*time.Hour), cleanupNow.Add(-3*time.Hour),
	)
	insertPostgreSQLAppAttestCleanupReceipt(
		t, fixture, recentID, otherExpiredToken,
		cleanupNow.Add(-3*time.Hour), cleanupNow.Add(-2*time.Hour),
	)
	insertPostgreSQLAppAttestCleanupReceipt(
		t, fixture, oldWithReceiptID, liveToken,
		cleanupNow.Add(-time.Hour), cleanupNow.Add(time.Hour),
	)

	locked, err := fixture.pool.BeginTx(fixture.ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("begin cleanup lock transaction: %v", err)
	}
	t.Cleanup(func() { rollbackAppAttestKeyTransaction(locked) })
	var lockedToken []byte
	if err := locked.QueryRow(fixture.ctx, `
		SELECT commit_token
		FROM app_attest_key_commit_receipts
		WHERE commit_token = $1
		FOR UPDATE
	`, lockedExpiredToken[:]).Scan(&lockedToken); err != nil {
		t.Fatalf("lock oldest expired receipt: %v", err)
	}
	cleanupCtx, cancelCleanup := context.WithTimeout(fixture.ctx, 2*time.Second)
	defer cancelCleanup()
	deleted, err := fixture.store.DeleteExpired(cleanupCtx, cleanupNow, 1)
	if err != nil || deleted != 1 {
		t.Fatalf("cleanup around locked receipt deleted=%d err=%v", deleted, err)
	}
	assertPostgreSQLAppAttestCleanupReceiptExists(t, fixture, lockedExpiredToken, true)
	assertPostgreSQLAppAttestCleanupReceiptExists(t, fixture, otherExpiredToken, false)
	if err := locked.Rollback(fixture.ctx); err != nil {
		t.Fatalf("release cleanup receipt lock: %v", err)
	}

	deleted, err = fixture.store.DeleteExpired(fixture.ctx, cleanupNow, 1)
	if err != nil || deleted != 1 {
		t.Fatalf("cleanup unlocked expired receipt deleted=%d err=%v", deleted, err)
	}
	assertPostgreSQLAppAttestCleanupReceiptExists(t, fixture, lockedExpiredToken, false)
	deleted, err = fixture.store.DeleteExpired(fixture.ctx, cleanupNow, 1)
	if err != nil || deleted != 1 {
		t.Fatalf("cleanup old orphan deleted=%d err=%v", deleted, err)
	}
	deleted, err = fixture.store.DeleteExpired(fixture.ctx, cleanupNow, 100)
	if err != nil || deleted != 0 {
		t.Fatalf("terminal cleanup deleted=%d err=%v", deleted, err)
	}

	assertPostgreSQLAppAttestCleanupKeyExists(t, fixture, oldOrphan, false)
	assertPostgreSQLAppAttestCleanupKeyExists(t, fixture, oldWithReceipt, true)
	assertPostgreSQLAppAttestCleanupKeyExists(t, fixture, linkedOld, true)
	assertPostgreSQLAppAttestCleanupKeyExists(t, fixture, recent, true)
	assertPostgreSQLAppAttestCleanupReceiptExists(t, fixture, liveToken, true)

	for _, invalid := range []struct {
		ctx    context.Context
		before time.Time
		limit  int
	}{
		{ctx: nil, before: cleanupNow, limit: 1},
		{ctx: fixture.ctx, before: time.Time{}, limit: 1},
		{ctx: fixture.ctx, before: time.Date(1, 1, 1, 0, 0, 0, 0, time.FixedZone("+14", 14*60*60)), limit: 1},
		{ctx: fixture.ctx, before: cleanupNow.Add(time.Hour), limit: 1},
		{ctx: fixture.ctx, before: cleanupNow, limit: 0},
		{ctx: fixture.ctx, before: cleanupNow, limit: maximumAppAttestCleanupBatch + 1},
	} {
		if _, err := fixture.store.DeleteExpired(invalid.ctx, invalid.before, invalid.limit); !errors.Is(err, ErrAppAttestKeyStore) {
			t.Fatalf("invalid cleanup input error=%v", err)
		}
	}
	assertPostgreSQLAppAttestCleanupKeyExists(t, fixture, oldWithReceipt, true)
	assertPostgreSQLAppAttestCleanupReceiptExists(t, fixture, liveToken, true)
	canceled, cancel := context.WithCancel(fixture.ctx)
	cancel()
	if _, err := fixture.store.DeleteExpired(canceled, cleanupNow, 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cleanup error=%v", err)
	}
}

type postgreSQLAppAttestFixture struct {
	ctx             context.Context
	pool            *pgxpool.Pool
	store           *PostgreSQLAppAttestKeyStore
	keyID           [sha256.Size]byte
	state           AppAttestStoredKey
	organizationID  string
	applicationID   string
	environmentID   string
	applicationUser string
}

func newPostgreSQLAppAttestFixture(t *testing.T) postgreSQLAppAttestFixture {
	t.Helper()
	ctx, pool := newAppAttestPostgreSQLPool(t)
	fixture := postgreSQLAppAttestFixture{
		ctx: ctx, pool: pool,
		organizationID:  mustAppAttestPostgreSQLID(t, id.Organization),
		applicationID:   mustAppAttestPostgreSQLID(t, id.Application),
		environmentID:   mustAppAttestPostgreSQLID(t, id.Environment),
		applicationUser: mustAppAttestPostgreSQLID(t, id.ApplicationUser),
	}
	createdAt := time.Date(2026, 8, 28, 9, 0, 0, 0, time.UTC)
	statements := []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO organizations (organization_id, slug, display_name, created_at, updated_at)
		  VALUES ($1, 'app-attest-test', 'App Attest Test', $2, $2)`, []any{fixture.organizationID, createdAt}},
		{`INSERT INTO applications (application_id, organization_id, slug, display_name, created_at, updated_at)
		  VALUES ($1, $2, 'mobile-app', 'Mobile App', $3, $3)`, []any{fixture.applicationID, fixture.organizationID, createdAt}},
		{`INSERT INTO environments (environment_id, organization_id, application_id, slug, display_name, kind, created_at, updated_at)
		  VALUES ($1, $2, $3, 'production', 'Production', 'production', $4, $4)`, []any{fixture.environmentID, fixture.organizationID, fixture.applicationID, createdAt}},
		{`INSERT INTO application_users (application_user_id, organization_id, application_id, created_at, updated_at)
		  VALUES ($1, $2, $3, $4, $4)`, []any{fixture.applicationUser, fixture.organizationID, fixture.applicationID, createdAt}},
	}
	for _, statement := range statements {
		if _, err := pool.Exec(ctx, statement.sql, statement.args...); err != nil {
			t.Fatalf("seed App Attest tenant: %v", err)
		}
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate App Attest persistence key: %v", err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y)
	fixture.keyID = sha256.Sum256(publicKey)
	fixture.state = AppAttestStoredKey{
		PublicKeyX963:          append([]byte(nil), publicKey...),
		AppIDHash:              sha256.Sum256([]byte("ABCDE12345.com.latchway.fixture")),
		AttestationEnvironment: AppAttestProduction,
		ApplicationID:          fixture.applicationID,
		EnvironmentID:          "production",
		Platform:               "react_native_ios",
		PrincipalID:            fixture.applicationUser,
		DPoPJKT:                appAttestPostgreSQLThumbprint("fixture DPoP key"),
		Counter:                0,
		ExtensionsPresent:      true,
		ValidationCategory:     4,
		BundleVersion:          "1.0.216",
		AttestedAt:             time.Date(2026, 8, 28, 9, 5, 6, 123456789, time.FixedZone("fixture", 7*60*60)).UTC(),
	}
	fixture.store, err = NewPostgreSQLAppAttestKeyStore(pool)
	if err != nil {
		t.Fatalf("construct App Attest key store: %v", err)
	}
	return fixture
}

func snapshotPostgreSQLAppAttestKey(t *testing.T, fixture postgreSQLAppAttestFixture) AppAttestStoredKey {
	t.Helper()
	errSnapshot := errors.New("snapshot only")
	var snapshot AppAttestStoredKey
	callbackCalls := 0
	err := fixture.store.TransactAppAttestKey(fixture.ctx, fixture.keyID, func(
		current AppAttestStoredKey,
		exists bool,
	) (AppAttestStoredKey, error) {
		callbackCalls++
		if !exists {
			t.Fatal("snapshot key does not exist")
		}
		snapshot = cloneAppAttestStoredKey(current)
		return current, errSnapshot
	})
	if !errors.Is(err, errSnapshot) || callbackCalls != 1 {
		t.Fatalf("snapshot transaction err=%v callbacks=%d", err, callbackCalls)
	}
	return snapshot
}

func assertPostgreSQLAppAttestKeyCount(t *testing.T, fixture postgreSQLAppAttestFixture, want int) {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT count(*) FROM attestation_keys WHERE provider_key_hash = $1
	`, fixture.keyID[:]).Scan(&count); err != nil || count != want {
		t.Fatalf("App Attest key count=%d err=%v want=%d", count, err, want)
	}
}

func assertPostgreSQLAppAttestReceiptCount(t *testing.T, fixture postgreSQLAppAttestFixture, want int) {
	t.Helper()
	var count int
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT count(*) FROM app_attest_key_commit_receipts
	`).Scan(&count); err != nil || count != want {
		t.Fatalf("App Attest commit receipt count=%d err=%v want=%d", count, err, want)
	}
}

func insertPostgreSQLAppAttestCleanupKey(
	t *testing.T,
	fixture postgreSQLAppAttestFixture,
	createdAt time.Time,
	linked bool,
) ([sha256.Size]byte, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate cleanup App Attest key: %v", err)
	}
	publicKey := elliptic.Marshal(elliptic.P256(), privateKey.X, privateKey.Y)
	keyID := sha256.Sum256(publicKey)
	attestationKeyID := mustAppAttestPostgreSQLID(t, id.AttestationKey)
	dpopJKT := appAttestPostgreSQLThumbprint(base64.RawURLEncoding.EncodeToString(keyID[:]))
	var installationID any
	var linkedAt any
	updatedAt := createdAt
	if linked {
		value := mustAppAttestPostgreSQLID(t, id.Installation)
		installationID = value
		linkedAt = createdAt.Add(time.Minute)
		updatedAt = linkedAt.(time.Time)
		if _, err := fixture.pool.Exec(fixture.ctx, `
			INSERT INTO installations (
				installation_id, organization_id, application_id, environment_id,
				application_user_id, platform, dpop_jkt, dpop_public_jwk,
				key_storage, trust_level, created_at, updated_at, last_seen_at
			) VALUES ($1, $2, $3, $4, $5, 'react_native_ios', $6, '{}'::jsonb,
			          'secure_enclave', 'app_verified', $7, $7, $7)
		`, value, fixture.organizationID, fixture.applicationID, fixture.environmentID,
			fixture.applicationUser, dpopJKT, createdAt); err != nil {
			t.Fatalf("insert linked cleanup installation: %v", err)
		}
	}
	if _, err := fixture.pool.Exec(fixture.ctx, `
		INSERT INTO attestation_keys (
			attestation_key_id, organization_id, application_id, environment_id,
			application_user_id, installation_id, provider, provider_key_id,
			provider_key_hash, public_key, app_id_hash, environment,
			binding_environment, platform, dpop_jkt, sign_count, status,
			extensions_present, validation_category, bundle_version,
			attested_at_unix_seconds, attested_at_nanosecond,
			created_at, updated_at, linked_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, 'app_attest', $7, $8, $9, $10,
			'production', 'production', 'react_native_ios', $11, 0, 'active',
			true, 4, '1.0', $12, $13, $14, $15, $16
		)
	`, attestationKeyID, fixture.organizationID, fixture.applicationID,
		fixture.environmentID, fixture.applicationUser, installationID,
		base64.StdEncoding.EncodeToString(keyID[:]), keyID[:], publicKey,
		fixture.state.AppIDHash[:], dpopJKT, fixture.state.AttestedAt.Unix(),
		int32(fixture.state.AttestedAt.Nanosecond()), createdAt, updatedAt, linkedAt); err != nil {
		t.Fatalf("insert cleanup App Attest key: %v", err)
	}
	return keyID, attestationKeyID
}

func insertPostgreSQLAppAttestCleanupReceipt(
	t *testing.T,
	fixture postgreSQLAppAttestFixture,
	attestationKeyID string,
	token [sha256.Size]byte,
	committedAt, expiresAt time.Time,
) {
	t.Helper()
	if _, err := fixture.pool.Exec(fixture.ctx, `
		INSERT INTO app_attest_key_commit_receipts (
			commit_token, organization_id, application_id, environment_id,
			attestation_key_id, sign_count, committed_at, expires_at
		) VALUES ($1, $2, $3, $4, $5, 0, $6, $7)
	`, token[:], fixture.organizationID, fixture.applicationID, fixture.environmentID,
		attestationKeyID, committedAt, expiresAt); err != nil {
		t.Fatalf("insert cleanup App Attest receipt: %v", err)
	}
}

func assertPostgreSQLAppAttestCleanupKeyExists(
	t *testing.T,
	fixture postgreSQLAppAttestFixture,
	keyID [sha256.Size]byte,
	want bool,
) {
	t.Helper()
	var exists bool
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT EXISTS (
			SELECT 1 FROM attestation_keys
			WHERE provider = 'app_attest' AND provider_key_hash = $1
		)
	`, keyID[:]).Scan(&exists); err != nil || exists != want {
		t.Fatalf("cleanup App Attest key %x exists=%v err=%v want=%v", keyID, exists, err, want)
	}
}

func assertPostgreSQLAppAttestCleanupReceiptExists(
	t *testing.T,
	fixture postgreSQLAppAttestFixture,
	token [sha256.Size]byte,
	want bool,
) {
	t.Helper()
	var exists bool
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT EXISTS (
			SELECT 1 FROM app_attest_key_commit_receipts WHERE commit_token = $1
		)
	`, token[:]).Scan(&exists); err != nil || exists != want {
		t.Fatalf("cleanup App Attest receipt %x exists=%v err=%v want=%v", token, exists, err, want)
	}
}

func postgreSQLAppAttestRowVersion(
	t *testing.T,
	fixture postgreSQLAppAttestFixture,
) (string, time.Time) {
	t.Helper()
	var version string
	var updatedAt time.Time
	if err := fixture.pool.QueryRow(fixture.ctx, `
		SELECT xmin::text, updated_at
		FROM attestation_keys
		WHERE provider = 'app_attest' AND provider_key_hash = $1
	`, fixture.keyID[:]).Scan(&version, &updatedAt); err != nil {
		t.Fatalf("read App Attest key row version: %v", err)
	}
	return version, updatedAt
}

func appAttestPostgreSQLThumbprint(label string) string {
	hash := sha256.Sum256([]byte(label))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func mustAppAttestPostgreSQLID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("generate %s ID: %v", prefix, err)
	}
	return value
}

func newAppAttestPostgreSQLPool(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	t.Cleanup(cancel)
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect App Attest test database: %v", err)
	}
	t.Cleanup(adminPool.Close)
	schema := fmt.Sprintf("latchway_app_attest_%d", time.Now().UnixNano())
	if !appAttestPostgreSQLSchemaPattern.MatchString(schema) {
		t.Fatalf("unsafe App Attest test schema %q", schema)
	}
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create App Attest test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cleanupCancel()
		_, _ = adminPool.Exec(cleanupCtx, "DROP SCHEMA "+schema+" CASCADE")
	})
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		t.Fatalf("parse App Attest database URL: %v", err)
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	pool, err := database.Open(ctx, parsed.String(), 8)
	if err != nil {
		t.Fatalf("open App Attest isolated database pool: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := database.NewMigrator(pool).Up(ctx); err != nil {
		t.Fatalf("migrate App Attest isolated database: %v", err)
	}
	return ctx, pool
}
