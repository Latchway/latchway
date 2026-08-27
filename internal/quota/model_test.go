package quota

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/requestidentity"
)

func TestPrepareRequestCanonicalizesTrustedBucketIdentity(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	input.Rules[0].Scope = []string{"feature", "user", "environment"}
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare request: %v", err)
	}
	if got, want := strings.Join(prepared.scopeDimensions, ","), "environment,user,feature"; got != want {
		t.Fatalf("scope dimensions = %q, want %q", got, want)
	}
	if prepared.scopeType != "composite" || len(prepared.ruleKey) != 43 || len(prepared.scopeKey) != 43 || prepared.ruleKey == prepared.scopeKey {
		t.Fatalf("unexpected bucket identity: %#v", prepared)
	}

	reordered := input
	reordered.Rules = []Rule{input.Rules[0]}
	reordered.Rules[0].Scope = []string{"environment", "feature", "user"}
	canonical, err := prepareRequest(reordered)
	if err != nil {
		t.Fatalf("prepare reordered request: %v", err)
	}
	if canonical.ruleKey != prepared.ruleKey || canonical.scopeKey != prepared.scopeKey {
		t.Fatal("scope order changed a canonical digest")
	}

	changedMaximum := input
	changedMaximum.Rules = []Rule{input.Rules[0]}
	changedMaximum.Rules[0].Maximum++
	maximumPrepared, err := prepareRequest(changedMaximum)
	if err != nil {
		t.Fatalf("prepare changed maximum: %v", err)
	}
	if maximumPrepared.ruleKey != prepared.ruleKey || maximumPrepared.scopeKey != prepared.scopeKey {
		t.Fatal("mutable maximum changed persistent quota identity")
	}

	changedFeature := input
	changedFeature.FeatureKey = "other-feature"
	featurePrepared, err := prepareRequest(changedFeature)
	if err != nil {
		t.Fatalf("prepare changed feature: %v", err)
	}
	if featurePrepared.ruleKey != prepared.ruleKey || featurePrepared.scopeKey == prepared.scopeKey {
		t.Fatal("server-owned scope value was omitted from scope identity")
	}
}

func TestRequestFingerprintBindsOpaqueLogicalIdentityAndTrustedDecision(t *testing.T) {
	t.Parallel()
	input := validReserveInput(t)
	prepared, err := prepareRequest(input)
	if err != nil {
		t.Fatalf("prepare request: %v", err)
	}
	fingerprint := requestFingerprint(prepared)
	if len(fingerprint) != 43 {
		t.Fatalf("fingerprint length = %d, want 43", len(fingerprint))
	}

	changedHint := cloneReserveInput(input)
	changedHint.ClientRequestID = "different-client-hint"
	hintPrepared, err := prepareRequest(changedHint)
	if err != nil {
		t.Fatalf("prepare changed hint: %v", err)
	}
	if hintPrepared.LogicalRequestID.String() != input.LogicalRequestID.String() {
		t.Fatal("client hint changed the opaque logical request identity")
	}
	if requestFingerprint(hintPrepared) == fingerprint {
		t.Fatal("durable client correlation was omitted from replay comparison")
	}

	changedLogicalID := cloneReserveInput(input)
	changedLogicalID.LogicalRequestID = mustLogicalID(t)
	logicalPrepared, err := prepareRequest(changedLogicalID)
	if err != nil {
		t.Fatalf("prepare changed logical ID: %v", err)
	}
	if requestFingerprint(logicalPrepared) == fingerprint {
		t.Fatal("opaque logical request identity was omitted from fingerprint")
	}
}

func TestPrepareRequestRejectsUnsupportedAndAmbiguousRules(t *testing.T) {
	t.Parallel()
	base := validReserveInput(t)
	tests := []struct {
		name   string
		mutate func(*ReserveInput)
	}{
		{name: "organization", mutate: func(input *ReserveInput) { input.OrganizationID = "invalid" }},
		{name: "logical request", mutate: func(input *ReserveInput) { input.LogicalRequestID = requestidentity.LogicalID{} }},
		{name: "application", mutate: func(input *ReserveInput) { input.ApplicationID = "invalid" }},
		{name: "environment", mutate: func(input *ReserveInput) { input.EnvironmentID = "invalid" }},
		{name: "user", mutate: func(input *ReserveInput) { input.ApplicationUserID = "invalid" }},
		{name: "installation", mutate: func(input *ReserveInput) { input.InstallationID = "invalid" }},
		{name: "grant", mutate: func(input *ReserveInput) { input.SessionGrantID = "invalid" }},
		{name: "revision", mutate: func(input *ReserveInput) { input.ConfigRevisionID = "invalid" }},
		{name: "feature", mutate: func(input *ReserveInput) { input.FeatureKey = "Not-Canonical" }},
		{name: "protocol", mutate: func(input *ReserveInput) { input.Protocol = "invented" }},
		{name: "client correlation", mutate: func(input *ReserveInput) { input.ClientRequestID = "bad hint" }},
		{name: "plan", mutate: func(input *ReserveInput) { input.LimitPlanKey = "Premium" }},
		{name: "route", mutate: func(input *ReserveInput) { input.RouteKey = "" }},
		{name: "upstream", mutate: func(input *ReserveInput) { input.UpstreamKey = "UPSTREAM" }},
		{name: "model", mutate: func(input *ReserveInput) { input.ModelKey = "" }},
		{name: "physical model", mutate: func(input *ReserveInput) { input.PhysicalModel = "model\nsecret" }},
		{name: "no rules", mutate: func(input *ReserveInput) { input.Rules = nil }},
		{name: "ambiguous rules", mutate: func(input *ReserveInput) { input.Rules = append(input.Rules, input.Rules[0]) }},
		{name: "metric", mutate: func(input *ReserveInput) { input.Rules[0].Metric = "total_tokens" }},
		{name: "algorithm", mutate: func(input *ReserveInput) { input.Rules[0].Algorithm = "token_bucket" }},
		{name: "soft", mutate: func(input *ReserveInput) { input.Rules[0].Hard = false }},
		{name: "zero maximum", mutate: func(input *ReserveInput) { input.Rules[0].Maximum = 0 }},
		{name: "empty scope", mutate: func(input *ReserveInput) { input.Rules[0].Scope = nil }},
		{name: "duplicate scope", mutate: func(input *ReserveInput) { input.Rules[0].Scope = []string{"user", "user"} }},
		{name: "unknown scope", mutate: func(input *ReserveInput) { input.Rules[0].Scope = []string{"claim"} }},
		{name: "invalid window", mutate: func(input *ReserveInput) { input.Rules[0].Window = "daily" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneReserveInput(base)
			test.mutate(&input)
			if _, err := prepareRequest(input); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("invalid input returned %v", err)
			}
		})
	}
}

func TestOutcomeValidation(t *testing.T) {
	t.Parallel()
	for _, outcome := range []Outcome{
		{Status: AttemptSucceeded, HTTPStatus: 200},
		{Status: AttemptFailed, HTTPStatus: 503, FailureCode: "upstream_unavailable"},
		{Status: AttemptCancelled, FailureCode: "client_cancelled"},
		{Status: AttemptTimedOut, FailureCode: "upstream_timeout"},
	} {
		if err := outcome.validate(); err != nil {
			t.Fatalf("valid outcome %#v: %v", outcome, err)
		}
	}
	for _, outcome := range []Outcome{
		{},
		{Status: AttemptSucceeded},
		{Status: AttemptSucceeded, HTTPStatus: 199},
		{Status: AttemptSucceeded, HTTPStatus: 302},
		{Status: AttemptSucceeded, HTTPStatus: 500},
		{Status: AttemptSucceeded, FailureCode: "unexpected"},
		{Status: AttemptFailed},
		{Status: AttemptFailed, HTTPStatus: 99, FailureCode: "failed"},
		{Status: AttemptTimedOut, FailureCode: "Bad Code"},
	} {
		if err := outcome.validate(); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid outcome %#v returned %v", outcome, err)
		}
	}
}

func validReserveInput(t *testing.T) ReserveInput {
	t.Helper()
	mustID := func(prefix id.Prefix) string {
		value, err := id.New(prefix)
		if err != nil {
			t.Fatalf("generate %s ID: %v", prefix, err)
		}
		return value
	}
	return ReserveInput{
		LogicalRequestID: mustLogicalID(t),
		OrganizationID:   mustID(id.Organization), ApplicationID: mustID(id.Application),
		EnvironmentID: mustID(id.Environment), ApplicationUserID: mustID(id.ApplicationUser),
		InstallationID: mustID(id.Installation), SessionGrantID: mustID(id.SessionGrant),
		ConfigRevisionID: mustID(id.ConfigRevision), FeatureKey: "assistant",
		Protocol: "openai_chat", ClientRequestID: "client-hint-123",
		LimitPlanKey: "free", RouteKey: "primary", UpstreamKey: "openrouter",
		ModelKey: "fast", PhysicalModel: "provider/model-v1",
		Rules: []Rule{{
			Metric: LogicalRequestsMetric, Algorithm: CalendarAlgorithm,
			Scope: []string{"user", "feature"}, Window: "1d", Maximum: 5, Hard: true,
		}},
	}
}

func mustLogicalID(t *testing.T) requestidentity.LogicalID {
	t.Helper()
	ctx, err := requestidentity.NewContext(context.Background())
	if err != nil {
		t.Fatalf("generate logical request identity: %v", err)
	}
	logicalID, ok := requestidentity.FromContext(ctx)
	if !ok {
		t.Fatal("generated logical request identity is missing")
	}
	return logicalID
}

func cloneReserveInput(input ReserveInput) ReserveInput {
	result := input
	result.Rules = append([]Rule(nil), input.Rules...)
	for index := range result.Rules {
		result.Rules[index].Scope = append([]string(nil), input.Rules[index].Scope...)
	}
	return result
}
