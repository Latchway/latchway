package configuration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
)

func TestStorePostgreSQLDraftLifecycle(t *testing.T) {
	databaseURL := os.Getenv("LATCHWAY_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("LATCHWAY_TEST_DATABASE_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedConfigurationPool(t, ctx, databaseURL)
	principal, scope := seedConfigurationTenant(t, ctx, pool)
	store, err := NewStore(pool)
	if err != nil {
		t.Fatal(err)
	}
	instant := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	store.now = func() time.Time { instant = instant.Add(time.Second); return instant }

	activate := func(revision Revision, options ...ActivationOption) Revision {
		t.Helper()
		if report, err := store.ValidateRevision(ctx, principal, revision.ID); err != nil || !report.Valid {
			t.Fatalf("ValidateRevision(%s) report=%+v error=%v", revision.ID, report, err)
		}
		current, err := store.GetRevision(ctx, principal, revision.ID)
		if err != nil {
			t.Fatal(err)
		}
		activated, err := store.ActivateRevision(ctx, principal, revision.ID, current.ETag, options...)
		if err != nil {
			t.Fatalf("ActivateRevision(%s) error = %v", revision.ID, err)
		}
		return activated
	}

	initial, err := store.CreateRevision(ctx, principal, CreateInput{EnvironmentID: scope.EnvironmentID, Document: validConfigurationDocument(t), Description: "first"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.ActivateRevision(ctx, principal, initial.ID, initial.ETag, WithActivationNote("bell\a")); !errors.Is(err, ErrInvalid) {
		t.Fatalf("activation with an invalid note error = %v", err)
	}
	live := activate(initial, WithActivationNote("  First release.  "))
	if live.ActivationNote != "First release." {
		t.Fatalf("activation note = %q", live.ActivationNote)
	}
	if _, err := pool.Exec(ctx, `UPDATE config_revisions SET activation_note = 'rewritten' WHERE config_revision_id = $1`, live.ID); err == nil {
		t.Fatal("an activated revision's publish note was rewritten")
	}

	// A validated draft that was never activated stays editable and returns to draft.
	draft, err := store.CreateRevision(ctx, principal, CreateInput{EnvironmentID: scope.EnvironmentID, BaseRevisionID: live.ID, Description: "Admin console draft"})
	if err != nil {
		t.Fatal(err)
	}
	if draft.BaseRevisionID != live.ID || draft.Description != "Admin console draft" {
		t.Fatalf("draft base=%q description=%q", draft.BaseRevisionID, draft.Description)
	}
	if report, err := store.ValidateRevision(ctx, principal, draft.ID); err != nil || !report.Valid {
		t.Fatalf("validate draft report=%+v err=%v", report, err)
	}
	validated, err := store.GetRevision(ctx, principal, draft.ID)
	if err != nil || validated.State != StateValid {
		t.Fatalf("validated draft state=%s err=%v", validated.State, err)
	}
	edited, err := store.ReplaceDraft(ctx, principal, draft.ID, validated.ETag, documentWithDescription(t, "second save"))
	if err != nil || edited.State != StateDraft || edited.Validation != nil {
		t.Fatalf("edit after validation state=%s err=%v", edited.State, err)
	}
	edits, err := store.ListRevisionEdits(ctx, principal, draft.ID)
	if err != nil || len(edits.Items) != 2 || edits.Items[0].Kind != editKindEdited || edits.Items[0].Version != 2 ||
		edits.Items[0].EditedBy != principal.AdminUserID || edits.Items[1].Kind != editKindCreated ||
		!slices.ContainsFunc(edits.Items[0].Changes, func(change PlanChange) bool { return change.Path == "/metadata/description" }) {
		t.Fatalf("edit history = %+v err=%v", edits, err)
	}
	reread, err := store.GetRevision(ctx, principal, draft.ID)
	if err != nil || !reread.UpdatedAt.Equal(edits.Items[0].EditedAt) || reread.UpdatedBy != principal.AdminUserID {
		t.Fatalf("revision updated_at=%s updated_by=%s err=%v", reread.UpdatedAt, reread.UpdatedBy, err)
	}

	// Discarding tombstones the draft; nothing can change or use it afterwards.
	if _, err := store.DiscardRevision(ctx, principal, draft.ID, `"stale"`); !errors.Is(err, ErrETagMismatch) {
		t.Fatalf("discard with a stale ETag error = %v", err)
	}
	if _, err := store.DiscardRevision(ctx, principal, live.ID, live.ETag); !errors.Is(err, ErrConflict) {
		t.Fatalf("discard of the live revision error = %v", err)
	}
	discarded, err := store.DiscardRevision(ctx, principal, draft.ID, edited.ETag)
	if err != nil || discarded.State != StateDiscarded || discarded.DiscardedBy != principal.AdminUserID || discarded.DiscardedAt == nil {
		t.Fatalf("discard state=%s by=%q err=%v", discarded.State, discarded.DiscardedBy, err)
	}
	if _, err := store.ReplaceDraft(ctx, principal, draft.ID, edited.ETag, validConfigurationDocument(t)); !errors.Is(err, ErrConflict) {
		t.Fatalf("edit of a discarded draft error = %v", err)
	}
	if _, err := store.ValidateRevision(ctx, principal, draft.ID); !errors.Is(err, ErrConflict) {
		t.Fatalf("validation of a discarded draft error = %v", err)
	}
	if _, err := store.SimulationSnapshot(ctx, principal, draft.ID); !errors.Is(err, ErrConfigurationInvalid) {
		t.Fatalf("simulation of a discarded draft error = %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE config_revisions SET status = 'draft' WHERE config_revision_id = $1`, draft.ID); err == nil {
		t.Fatal("a discarded revision was revived")
	}
	// A validated, never-activated draft can be discarded too.
	validDraft, err := store.CreateRevision(ctx, principal, CreateInput{EnvironmentID: scope.EnvironmentID, BaseRevisionID: live.ID})
	if err != nil {
		t.Fatal(err)
	}
	if report, err := store.ValidateRevision(ctx, principal, validDraft.ID); err != nil || !report.Valid {
		t.Fatalf("validate second draft report=%+v err=%v", report, err)
	}
	if validDraft, err = store.GetRevision(ctx, principal, validDraft.ID); err != nil {
		t.Fatal(err)
	}
	if discardedValid, err := store.DiscardRevision(ctx, principal, validDraft.ID, validDraft.ETag); err != nil || discardedValid.State != StateDiscarded {
		t.Fatalf("discard of a validated draft state=%s err=%v", discardedValid.State, err)
	}

	// A draft goes stale when something else is published; rebase merges it.
	stale, err := store.CreateRevision(ctx, principal, CreateInput{EnvironmentID: scope.EnvironmentID, Document: configurationDocumentWithPremiumPlan(t, "draft description")})
	if err != nil {
		t.Fatal(err)
	}
	competing, err := store.CreateRevision(ctx, principal, CreateInput{EnvironmentID: scope.EnvironmentID, Document: documentWithDescription(t, "live description")})
	if err != nil {
		t.Fatal(err)
	}
	newLive := activate(competing)
	if current, _ := store.GetRevision(ctx, principal, stale.ID); current.BaseRevisionID != live.ID {
		t.Fatalf("stale draft base = %q", current.BaseRevisionID)
	}
	preview, err := store.RebasePreview(ctx, principal, stale.ID)
	if err != nil || preview.UpToDate || preview.LiveRevisionID != newLive.ID || preview.BaseRevisionID != live.ID ||
		!slices.Equal(preview.Conflicts, []string{"/metadata/description"}) ||
		!slices.ContainsFunc(preview.DraftChanges, func(change PlanChange) bool { return change.Path == "/spec/limitPlans/premium" }) {
		t.Fatalf("rebase preview = %+v err=%v", preview, err)
	}
	if _, err := store.Rebase(ctx, principal, stale.ID, stale.ETag, newLive.ID, nil); !errors.Is(err, ErrMergeConflict) {
		t.Fatalf("rebase without resolutions error = %v", err)
	}
	if _, err := store.Rebase(ctx, principal, stale.ID, stale.ETag, live.ID, map[string]string{"/metadata/description": MergeTakeLive}); !errors.Is(err, ErrConflict) {
		t.Fatalf("rebase onto a revision that is no longer live error = %v", err)
	}
	rebased, err := store.Rebase(ctx, principal, stale.ID, stale.ETag, newLive.ID, map[string]string{"/metadata/description": MergeTakeLive})
	if err != nil || rebased.BaseRevisionID != newLive.ID || rebased.ETag == stale.ETag {
		t.Fatalf("rebase base=%q err=%v", rebased.BaseRevisionID, err)
	}
	var merged map[string]any
	if err := json.Unmarshal(rebased.Document, &merged); err != nil {
		t.Fatal(err)
	}
	if objectValue(merged, "metadata")["description"] != "live description" ||
		!slices.ContainsFunc(objectArray(objectValue(merged, "spec"), "limitPlans"), func(plan map[string]any) bool { return plan["id"] == "premium" }) {
		t.Fatalf("rebased document = %s", rebased.Document)
	}
	if edits, _ := store.ListRevisionEdits(ctx, principal, stale.ID); len(edits.Items) == 0 || edits.Items[0].Kind != editKindRebased {
		t.Fatalf("rebase edit history = %+v", edits)
	}
	if upToDate, err := store.RebasePreview(ctx, principal, stale.ID); err != nil || !upToDate.UpToDate {
		t.Fatalf("rebased preview = %+v err=%v", upToDate, err)
	}
	activate(rebased)

	// Promotion copies the live configuration of another environment of the same application.
	stagingID := mustConfigID(t, id.Environment)
	if _, err := pool.Exec(ctx, `INSERT INTO environments (environment_id, organization_id, application_id, slug, display_name, kind, status, created_at, updated_at)
		VALUES ($1, $2, $3, 'staging', 'Staging', 'staging', 'active', $4, $4)`, stagingID, scope.OrganizationID, scope.ApplicationID, instant); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Promote(ctx, principal, PromoteInput{TargetEnvironmentID: stagingID, SourceEnvironmentID: stagingID}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("promotion into itself error = %v", err)
	}
	promoted, report, err := store.Promote(ctx, principal, PromoteInput{TargetEnvironmentID: stagingID, SourceEnvironmentID: scope.EnvironmentID, Description: "From production"})
	if err != nil || promoted.EnvironmentID != stagingID || promoted.BaseRevisionID != "" || report.SourceEnvironmentID != scope.EnvironmentID ||
		len(report.Review) == 0 || !slices.Contains(report.Kept, "/metadata") {
		t.Fatalf("promotion revision=%+v report=%+v err=%v", promoted, report, err)
	}
	var promotedDocument map[string]any
	if err := json.Unmarshal(promoted.Document, &promotedDocument); err != nil {
		t.Fatal(err)
	}
	if objectValue(promotedDocument, "metadata")["environment"] != "staging" {
		t.Fatalf("promoted metadata = %v", promotedDocument["metadata"])
	}
	if edits, _ := store.ListRevisionEdits(ctx, principal, promoted.ID); len(edits.Items) != 1 || edits.Items[0].Kind != editKindPromoted {
		t.Fatalf("promotion edit history = %+v", edits)
	}
	if _, _, err := store.Promote(ctx, principal, PromoteInput{TargetEnvironmentID: stagingID, SourceEnvironmentID: scope.EnvironmentID}); !errors.Is(err, ErrDraftPending) {
		t.Fatalf("promotion over a pending draft error = %v", err)
	}
	if _, _, err := store.Promote(ctx, principal, PromoteInput{TargetEnvironmentID: scope.EnvironmentID, SourceEnvironmentID: stagingID}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("promotion from an environment with nothing live error = %v", err)
	}
	viewer := principal
	viewer.Role = adminauth.RoleViewer
	if _, _, err := store.Promote(ctx, viewer, PromoteInput{TargetEnvironmentID: stagingID, SourceEnvironmentID: scope.EnvironmentID}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer promotion error = %v", err)
	}
	if _, err := store.DiscardRevision(ctx, viewer, promoted.ID, promoted.ETag); !errors.Is(err, ErrForbidden) {
		t.Fatalf("viewer discard error = %v", err)
	}
	if _, err := store.DiscardRevision(ctx, principal, promoted.ID, promoted.ETag); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Promote(ctx, principal, PromoteInput{TargetEnvironmentID: stagingID, SourceEnvironmentID: scope.EnvironmentID}); err != nil {
		t.Fatalf("promotion after discarding the pending draft error = %v", err)
	}
}
