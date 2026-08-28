package adminauth

import (
	"errors"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

func TestAuditChangesNeverCarryValues(t *testing.T) {
	t.Parallel()

	public, err := NewPublicAuditChange("display_name", AuditSet)
	if err != nil {
		t.Fatalf("NewPublicAuditChange() error = %v", err)
	}
	sensitive, err := NewSensitiveAuditChange("provider_secret", AuditRotate)
	if err != nil {
		t.Fatalf("NewSensitiveAuditChange() error = %v", err)
	}
	if public.Classification() != AuditPublic || sensitive.Classification() != AuditSensitive {
		t.Fatalf("unexpected classifications: %q %q", public.Classification(), sensitive.Classification())
	}
	if _, err := NewPublicAuditChange("refresh_token_hash", AuditSet); !errors.Is(err, ErrSensitiveAuditField) {
		t.Fatalf("public sensitive field error = %v", err)
	}
}

func TestAuditMutationValidationAndDefensiveCopies(t *testing.T) {
	t.Parallel()

	eventID := mustIdentifier(t, id.AuditEvent)
	organizationID := mustIdentifier(t, id.Organization)
	environmentID := mustIdentifier(t, id.Environment)
	adminUserID := mustIdentifier(t, id.AdminUser)
	requestID := mustIdentifier(t, id.AdminRequest)
	actor, err := NewAdminUserActor(adminUserID)
	if err != nil {
		t.Fatalf("NewAdminUserActor() error = %v", err)
	}
	change, err := NewSensitiveAuditChange("bootstrap_token", AuditConsume)
	if err != nil {
		t.Fatalf("NewSensitiveAuditChange() error = %v", err)
	}
	changes := []AuditChange{change}
	instant := time.Date(2026, 8, 27, 12, 0, 0, 0, time.FixedZone("offset", 7*60*60))
	mutation, err := NewAuditMutation(
		eventID,
		organizationID,
		environmentID,
		actor,
		"admin.bootstrap_owner",
		"admin_user",
		adminUserID,
		AuditSucceeded,
		requestID,
		instant,
		changes,
	)
	if err != nil {
		t.Fatalf("NewAuditMutation() error = %v", err)
	}
	changes[0] = AuditChange{}
	if mutation.Changes()[0].Field() != "bootstrap_token" {
		t.Fatal("constructor retained caller change slice")
	}
	returned := mutation.Changes()
	returned[0] = AuditChange{}
	if mutation.Changes()[0].Field() != "bootstrap_token" {
		t.Fatal("Changes returned internal slice")
	}
	if mutation.OccurredAt().Location() != time.UTC {
		t.Fatalf("OccurredAt location = %v", mutation.OccurredAt().Location())
	}
}

func TestAuditMutationAcceptsEveryCanonicalOutcome(t *testing.T) {
	t.Parallel()
	change, err := NewSensitiveAuditChange("credential", AuditSet)
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []AuditOutcome{AuditSucceeded, AuditDenied, AuditFailed, AuditIndeterminate} {
		outcome := outcome
		t.Run(string(outcome), func(t *testing.T) {
			t.Parallel()
			mutation, err := NewAuditMutation(
				mustIdentifier(t, id.AuditEvent), "", "", SystemActor(),
				"admin.secret_rotate", "admin_request", mustIdentifier(t, id.AdminRequest),
				outcome, mustIdentifier(t, id.AdminRequest), time.Now().UTC(), []AuditChange{change},
			)
			if err != nil || mutation.Outcome() != outcome {
				t.Fatalf("outcome=%q mutation=%+v err=%v", outcome, mutation, err)
			}
		})
	}
}

func TestAuditMutationRejectsUnsafeInput(t *testing.T) {
	t.Parallel()

	eventID := mustIdentifier(t, id.AuditEvent)
	organizationID := mustIdentifier(t, id.Organization)
	change, err := NewPublicAuditChange("name", AuditSet)
	if err != nil {
		t.Fatalf("NewPublicAuditChange() error = %v", err)
	}
	tests := []struct {
		name         string
		action       string
		resourceType string
		resourceID   string
		requestID    string
		occurredAt   time.Time
		changes      []AuditChange
	}{
		{name: "invalid action", action: "Admin Bootstrap", resourceType: "admin_user", resourceID: "user", occurredAt: time.Now(), changes: []AuditChange{change}},
		{name: "invalid resource type", action: "admin.bootstrap", resourceType: "Admin User", resourceID: "user", occurredAt: time.Now(), changes: []AuditChange{change}},
		{name: "empty resource", action: "admin.bootstrap", resourceType: "admin_user", occurredAt: time.Now(), changes: []AuditChange{change}},
		{name: "control request", action: "admin.bootstrap", resourceType: "admin_user", resourceID: "user", requestID: "bad\nrequest", occurredAt: time.Now(), changes: []AuditChange{change}},
		{name: "zero time", action: "admin.bootstrap", resourceType: "admin_user", resourceID: "user", changes: []AuditChange{change}},
		{name: "empty changes", action: "admin.bootstrap", resourceType: "admin_user", resourceID: "user", occurredAt: time.Now()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewAuditMutation(
				eventID,
				organizationID,
				"",
				SystemActor(),
				test.action,
				test.resourceType,
				test.resourceID,
				AuditSucceeded,
				test.requestID,
				test.occurredAt,
				test.changes,
			)
			if !errors.Is(err, ErrInvalidAuditMutation) {
				t.Fatalf("NewAuditMutation() error = %v", err)
			}
		})
	}
}

func mustIdentifier(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("id.New(%q) error = %v", prefix, err)
	}
	return value
}
