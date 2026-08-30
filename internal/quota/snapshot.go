package quota

import (
	"context"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/useroverride"
)

// SnapshotInput contains the exact active, server-resolved quota projection
// for one principal and feature. Rules describe policy only: ReservedUnits
// must be zero because a snapshot never represents or creates a reservation.
// RouteKey, UpstreamKey, and ModelKey are required only when a rule scopes on
// the corresponding dimension.
type SnapshotInput struct {
	OrganizationID         string
	ApplicationID          string
	EnvironmentID          string
	ApplicationUserID      string
	InstallationID         string
	ConfigRevisionID       string
	Platform               string
	NormalizedClaimDigests map[string]string
	UserOverrideID         string
	LimitPlanOverride      string

	FeatureKey   string
	LimitPlanKey string
	RouteKey     string
	UpstreamKey  string
	ModelKey     string

	Rules []Rule
}

// Snapshot is an authoritative point-in-time view of the selected quota
// rules. ObservedAt is PostgreSQL's transaction timestamp for the same
// repeatable-read snapshot from which all durable counters were read.
type Snapshot struct {
	Feature    string
	ObservedAt time.Time
	Limits     []LimitSnapshot
}

// LimitSnapshot deliberately exposes no rule, scope, plan, algorithm, rate,
// or durable bucket identity. Pointers preserve the public contract's
// distinction between an omitted counter and an explicit zero.
type LimitSnapshot struct {
	Metric    string
	Maximum   *int64
	Used      *int64
	Reserved  *int64
	Remaining *int64
	ResetsAt  *time.Time
	Hard      bool
}

type preparedSnapshot struct {
	SnapshotInput
	rules []preparedRule
}

type snapshotPlan struct {
	rule   preparedRule
	period calendarPeriod
	bucket *lockedBucket
}

// Snapshot returns quota state without taking row locks, writing reconciled
// token state, or materializing missing buckets. A missing stateful bucket is
// the pristine state selected by current policy. The active revision check and
// every bucket read share one read-only repeatable-read PostgreSQL snapshot.
func (store *Store) Snapshot(ctx context.Context, input SnapshotInput) (Snapshot, error) {
	if store == nil || store.pool == nil || ctx == nil {
		return Snapshot{}, ErrInvalidInput
	}
	prepared, err := prepareSnapshot(input)
	if err != nil {
		return Snapshot{}, err
	}

	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	})
	if err != nil {
		return Snapshot{}, persistenceFailure("begin quota snapshot", err)
	}
	defer rollback(tx)

	observedAt, err := snapshotTransactionTime(ctx, tx, prepared)
	if err != nil {
		return Snapshot{}, err
	}
	if err := verifySnapshotUserOverride(ctx, tx, prepared, observedAt); err != nil {
		return Snapshot{}, err
	}
	plans, err := snapshotPlansAt(prepared.rules, observedAt)
	if err != nil {
		return Snapshot{}, err
	}
	if err := loadSnapshotBuckets(ctx, tx, prepared, plans); err != nil {
		return Snapshot{}, err
	}

	result := Snapshot{
		Feature:    prepared.FeatureKey,
		ObservedAt: observedAt,
		Limits:     make([]LimitSnapshot, len(plans)),
	}
	for index := range plans {
		limit, err := limitSnapshotAt(plans[index], observedAt)
		if err != nil {
			return Snapshot{}, err
		}
		result.Limits[index] = limit
	}
	if err := tx.Commit(ctx); err != nil {
		return Snapshot{}, persistenceFailure("commit quota snapshot", err)
	}
	return result, nil
}

func prepareSnapshot(input SnapshotInput) (preparedSnapshot, error) {
	override := useroverride.Selection{
		ID: input.UserOverrideID, LimitPlan: input.LimitPlanOverride,
	}
	if id.Validate(input.OrganizationID, id.Organization) != nil ||
		id.Validate(input.ApplicationID, id.Application) != nil ||
		id.Validate(input.EnvironmentID, id.Environment) != nil ||
		id.Validate(input.ApplicationUserID, id.ApplicationUser) != nil ||
		id.Validate(input.InstallationID, id.Installation) != nil ||
		id.Validate(input.ConfigRevisionID, id.ConfigRevision) != nil ||
		!identifierPattern.MatchString(input.FeatureKey) ||
		!identifierPattern.MatchString(input.LimitPlanKey) ||
		override.Validate() != nil ||
		(override.Present() && override.LimitPlan != input.LimitPlanKey) {
		return preparedSnapshot{}, ErrInvalidInput
	}

	values, err := quotaScopeValues(map[string]string{
		"organization": input.OrganizationID,
		"application":  input.ApplicationID,
		"environment":  input.EnvironmentID,
		"user":         input.ApplicationUserID,
		"installation": input.InstallationID,
		"feature":      input.FeatureKey,
		"route":        input.RouteKey,
		"upstream":     input.UpstreamKey,
		"model":        input.ModelKey,
	}, input.Platform, input.NormalizedClaimDigests)
	if err != nil {
		return preparedSnapshot{}, err
	}
	rules, err := prepareRules(input.Rules, values, snapshotRulePreparation)
	if err != nil {
		return preparedSnapshot{}, err
	}
	for _, rule := range rules {
		for _, dimension := range rule.scopeDimensions {
			switch dimension {
			case "route", "upstream", "model":
				if !identifierPattern.MatchString(values[dimension]) {
					return preparedSnapshot{}, ErrInvalidInput
				}
			}
		}
	}

	input.NormalizedClaimDigests = cloneStringMap(input.NormalizedClaimDigests)
	prepared := preparedSnapshot{SnapshotInput: input, rules: rules}
	prepared.Rules = clonePreparedRules(rules)
	return prepared, nil
}

// verifySnapshotUserOverride binds the selected limit plan to the exact
// active override row (or its absence) at ObservedAt. Authorization seals this
// selection before policy evaluation; revalidating it in the same repeatable-
// read snapshot as the active revision and quota counters prevents a mutable
// override transition from producing a mixed point-in-time projection.
func verifySnapshotUserOverride(
	ctx context.Context,
	tx pgx.Tx,
	prepared preparedSnapshot,
	observedAt time.Time,
) error {
	expected := useroverride.Selection{
		ID: prepared.UserOverrideID, LimitPlan: prepared.LimitPlanOverride,
	}
	if err := expected.Validate(); err != nil || observedAt.IsZero() {
		return ErrInvalidInput
	}

	var actual useroverride.Selection
	var document []byte
	err := tx.QueryRow(ctx, `
		SELECT user_override_id, override_document
		FROM user_overrides
		WHERE organization_id = $1
		  AND application_id = $2
		  AND environment_id = $3
		  AND application_user_id = $4
		  AND revoked_at IS NULL
		  AND (expires_at IS NULL OR expires_at > $5)
	`, prepared.OrganizationID, prepared.ApplicationID, prepared.EnvironmentID,
		prepared.ApplicationUserID, observedAt).Scan(&actual.ID, &document)
	if errors.Is(err, pgx.ErrNoRows) {
		if expected.Present() {
			return ErrInvalidState
		}
		return nil
	}
	if err != nil {
		return persistenceFailure("verify active quota snapshot user override", err)
	}
	decoded, err := useroverride.Decode(document)
	if err != nil {
		return ErrInvalidState
	}
	actual.LimitPlan = decoded.LimitPlan
	if actual.Validate() != nil || !expected.Present() || actual != expected {
		return ErrInvalidState
	}
	return nil
}

// snapshotTransactionTime establishes the transaction's MVCC snapshot while
// binding the supplied policy to the revision that was active at ObservedAt.
// The timestamp predicates matter when activation commits after BEGIN but
// before this first statement: such a later revision must not be described as
// effective at an earlier transaction timestamp.
func snapshotTransactionTime(
	ctx context.Context,
	tx pgx.Tx,
	prepared preparedSnapshot,
) (time.Time, error) {
	var observedAt time.Time
	var active bool
	if err := tx.QueryRow(ctx, `
		SELECT transaction_timestamp(), EXISTS (
			SELECT 1
			FROM active_config_revisions AS active_revision
			JOIN config_revisions AS revision
			  ON revision.organization_id = active_revision.organization_id
			 AND revision.application_id = active_revision.application_id
			 AND revision.environment_id = active_revision.environment_id
			 AND revision.config_revision_id = active_revision.config_revision_id
			WHERE active_revision.organization_id = $1
			  AND active_revision.application_id = $2
			  AND active_revision.environment_id = $3
			  AND active_revision.config_revision_id = $4
			  AND active_revision.revision_status = 'valid'
			  AND revision.status = 'valid'
			  AND active_revision.activated_at <= transaction_timestamp()
			  AND revision.activated_at IS NOT NULL
			  AND revision.activated_at <= transaction_timestamp()
		)
	`, prepared.OrganizationID, prepared.ApplicationID, prepared.EnvironmentID,
		prepared.ConfigRevisionID).Scan(&observedAt, &active); err != nil {
		return time.Time{}, persistenceFailure("verify active quota snapshot revision", err)
	}
	observedAt = observedAt.UTC()
	if observedAt.IsZero() || !active {
		return time.Time{}, ErrInvalidState
	}
	return observedAt, nil
}

func snapshotPlansAt(rules []preparedRule, at time.Time) ([]snapshotPlan, error) {
	if len(rules) < 1 || len(rules) > maximumRulesPerRequest || at.IsZero() {
		return nil, ErrInvalidInput
	}
	ordered := append([]preparedRule(nil), rules...)
	sort.Slice(ordered, func(left, right int) bool {
		if ordered[left].Metric != ordered[right].Metric {
			return ordered[left].Metric < ordered[right].Metric
		}
		if ordered[left].ruleKey != ordered[right].ruleKey {
			return ordered[left].ruleKey < ordered[right].ruleKey
		}
		return ordered[left].scopeKey < ordered[right].scopeKey
	})
	plans := make([]snapshotPlan, len(ordered))
	for index := range ordered {
		plans[index].rule = ordered[index]
		if !ordered[index].stateful {
			continue
		}
		switch {
		case isConcurrencyMetric(ordered[index].Metric):
			plans[index].period.key = "active"
		case ordered[index].Algorithm == TokenBucketAlgorithm:
			plans[index].period.key = tokenBucketWindowKey
		default:
			period, err := calendarWindowIn(at, ordered[index].Window, ordered[index].Timezone)
			if err != nil {
				return nil, err
			}
			plans[index].period = period
		}
	}
	return plans, nil
}

func loadSnapshotBuckets(
	ctx context.Context,
	tx pgx.Tx,
	prepared preparedSnapshot,
	plans []snapshotPlan,
) error {
	stateful := make([]int, 0, len(plans))
	var ruleKeys, metrics, algorithms, windowKeys, scopeKeys []string
	for index := range plans {
		if !plans[index].rule.stateful {
			continue
		}
		stateful = append(stateful, index)
		ruleKeys = append(ruleKeys, plans[index].rule.ruleKey)
		metrics = append(metrics, plans[index].rule.Metric)
		algorithms = append(algorithms, plans[index].rule.Algorithm)
		windowKeys = append(windowKeys, plans[index].period.key)
		scopeKeys = append(scopeKeys, plans[index].rule.scopeKey)
	}
	if len(stateful) == 0 {
		return nil
	}

	rows, err := tx.Query(ctx, `
		SELECT requested.ordinality,
		       bucket.quota_bucket_id, bucket.organization_id, bucket.application_id,
		       bucket.hard_maximum, bucket.used_units, bucket.reserved_units,
		       bucket.available_units, bucket.refill_numerator,
		       bucket.refill_denominator, bucket.refilled_at, bucket.version,
		       bucket.scope_type, bucket.scope_dimensions
		FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::text[])
		     WITH ORDINALITY AS requested(
		         rule_key, metric, algorithm, window_key, scope_key, ordinality
		     )
		LEFT JOIN quota_buckets AS bucket
		  ON bucket.environment_id = $6
		 AND bucket.limit_plan_key = $7
		 AND bucket.rule_key = requested.rule_key
		 AND bucket.metric = requested.metric
		 AND bucket.algorithm = requested.algorithm
		 AND bucket.window_key = requested.window_key
		 AND bucket.scope_key = requested.scope_key
		ORDER BY requested.ordinality
	`, ruleKeys, metrics, algorithms, windowKeys, scopeKeys,
		prepared.EnvironmentID, prepared.LimitPlanKey)
	if err != nil {
		return persistenceFailure("read quota snapshot buckets", err)
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var ordinal int64
		var bucketID, organizationID, applicationID, scopeType *string
		var hardMaximum, used, reserved, available *int64
		var refillNumerator, refillDenominator, version *int64
		var refilledAt *time.Time
		var scopeDimensions []string
		if err := rows.Scan(
			&ordinal, &bucketID, &organizationID, &applicationID,
			&hardMaximum, &used, &reserved, &available,
			&refillNumerator, &refillDenominator, &refilledAt, &version,
			&scopeType, &scopeDimensions,
		); err != nil {
			return persistenceFailure("scan quota snapshot bucket", err)
		}
		if count >= len(stateful) || ordinal != int64(count+1) {
			return ErrInvalidState
		}
		plan := &plans[stateful[count]]
		count++
		if bucketID == nil {
			continue
		}
		if organizationID == nil || applicationID == nil || hardMaximum == nil ||
			used == nil || reserved == nil || version == nil || scopeType == nil {
			return ErrInvalidState
		}
		bucket := lockedBucket{
			id: *bucketID, hardMaximum: hardMaximum, used: *used, reserved: *reserved,
			available: available, refillNumerator: refillNumerator,
			refillDenominator: refillDenominator, refilledAt: refilledAt,
			version: *version, scopeType: *scopeType, scopeDimensions: scopeDimensions,
		}
		if err := validateSnapshotBucket(prepared, *plan, bucket, *organizationID, *applicationID); err != nil {
			return err
		}
		plan.bucket = &bucket
	}
	if err := rows.Err(); err != nil {
		return persistenceFailure("iterate quota snapshot buckets", err)
	}
	if count != len(stateful) {
		return ErrInvalidState
	}
	return nil
}

func validateSnapshotBucket(
	prepared preparedSnapshot,
	plan snapshotPlan,
	bucket lockedBucket,
	organizationID string,
	applicationID string,
) error {
	if organizationID != prepared.OrganizationID || applicationID != prepared.ApplicationID ||
		id.Validate(bucket.id, id.QuotaBucket) != nil || bucket.version < 0 ||
		bucket.scopeType != plan.rule.scopeType ||
		!slicesEqual(bucket.scopeDimensions, plan.rule.scopeDimensions) {
		return ErrInvalidState
	}
	if plan.rule.Algorithm == TokenBucketAlgorithm {
		_, err := tokenStateFromLockedBucket(bucket)
		return err
	}
	if bucket.hardMaximum == nil || *bucket.hardMaximum <= 0 || bucket.used < 0 ||
		bucket.reserved < 0 || bucket.used > math.MaxInt64-bucket.reserved ||
		bucket.used+bucket.reserved > *bucket.hardMaximum || bucket.available != nil ||
		bucket.refillNumerator != nil || bucket.refillDenominator != nil ||
		bucket.refilledAt != nil || (isConcurrencyMetric(plan.rule.Metric) && bucket.used != 0) {
		return ErrInvalidState
	}
	return nil
}

func limitSnapshotAt(plan snapshotPlan, observedAt time.Time) (LimitSnapshot, error) {
	limit := LimitSnapshot{Metric: plan.rule.Metric, Hard: plan.rule.Hard}
	if !plan.rule.stateful {
		maximum := plan.rule.PerRequestMaximum
		limit.Maximum = &maximum
		return limit, nil
	}

	if plan.rule.Algorithm == TokenBucketAlgorithm {
		maximum := plan.rule.Capacity
		remaining := maximum
		if plan.bucket != nil {
			stored, err := tokenStateFromLockedBucket(*plan.bucket)
			if err != nil {
				return LimitSnapshot{}, err
			}
			reconciled, err := reconcileTokenBucket(
				stored, plan.rule.Capacity, plan.rule.RefillNumerator,
				plan.rule.RefillDenominator, observedAt,
			)
			if err != nil {
				return LimitSnapshot{}, err
			}
			remaining = reconciled.balance / tokenBalanceScale
			if remaining < 0 || remaining > maximum {
				return LimitSnapshot{}, ErrInvalidState
			}
		}
		used, reserved := maximum-remaining, int64(0)
		limit.Maximum, limit.Used = &maximum, &used
		limit.Reserved, limit.Remaining = &reserved, &remaining
		return limit, nil
	}

	maximum := plan.rule.Maximum
	used, reserved := int64(0), int64(0)
	if plan.bucket != nil {
		used, reserved = plan.bucket.used, plan.bucket.reserved
	}
	remaining := int64(0)
	if used <= maximum && reserved <= maximum-used {
		remaining = maximum - used - reserved
	}
	limit.Maximum, limit.Used = &maximum, &used
	limit.Reserved, limit.Remaining = &reserved, &remaining
	if plan.rule.Algorithm == CalendarAlgorithm {
		reset := plan.period.end.UTC()
		if reset.IsZero() || !reset.After(observedAt) {
			return LimitSnapshot{}, ErrInvalidState
		}
		limit.ResetsAt = &reset
	}
	return limit, nil
}
