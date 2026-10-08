package configuration

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/jsonsafe"
)

const (
	editKindCreated  = "created"
	editKindEdited   = "edited"
	editKindRebased  = "rebased"
	editKindPromoted = "promoted"

	maximumRecordedEditChanges = 100
	maximumListedEdits         = 200
	maximumActivationNoteRunes = 500
)

// RevisionEdit is one recorded change to a draft: who made it, when, and
// which paths changed. Values are never recorded.
type RevisionEdit struct {
	Version     int64        `json:"version"`
	Kind        string       `json:"kind"`
	EditedAt    time.Time    `json:"edited_at"`
	EditedBy    string       `json:"edited_by"`
	ChangeCount int          `json:"change_count"`
	Changes     []PlanChange `json:"changes"`
}

// RevisionEdits is the newest-first edit history of one revision.
type RevisionEdits struct {
	RevisionID string         `json:"revision_id"`
	Items      []RevisionEdit `json:"items"`
	Truncated  bool           `json:"truncated"`
}

// MergePreview describes, by path only, what bringing a draft up to date
// with the live revision would combine and where both sides changed the same
// thing differently.
type MergePreview struct {
	RevisionID     string       `json:"revision_id"`
	BaseRevisionID string       `json:"base_revision_id,omitempty"`
	LiveRevisionID string       `json:"live_revision_id"`
	UpToDate       bool         `json:"up_to_date"`
	DraftChanges   []PlanChange `json:"draft_changes"`
	LiveChanges    []PlanChange `json:"live_changes"`
	Conflicts      []string     `json:"conflicts"`
}

// PromotionReport explains where each part of a promoted draft came from.
type PromotionReport struct {
	SourceEnvironmentID string   `json:"source_environment_id"`
	SourceRevisionID    string   `json:"source_revision_id"`
	Copied              []string `json:"copied"`
	Kept                []string `json:"kept"`
	Review              []string `json:"review"`
}

// ActivationOption adjusts one activation.
type ActivationOption func(*activationSettings)

type activationSettings struct {
	note string
}

// WithActivationNote records a publish note on the activated revision.
func WithActivationNote(note string) ActivationOption {
	return func(settings *activationSettings) { settings.note = note }
}

// ValidActivationNote reports whether note is a publish note the store
// accepts: 1 to 500 characters of text without control characters other than
// line breaks.
func ValidActivationNote(note string) bool {
	trimmed := strings.TrimSpace(note)
	if trimmed == "" || !utf8.ValidString(trimmed) || utf8.RuneCountInString(trimmed) > maximumActivationNoteRunes {
		return false
	}
	for _, character := range trimmed {
		if character != '\n' && unicode.IsControl(character) {
			return false
		}
	}
	return true
}

// editableRevision reports whether a revision's document may still change:
// a draft, an invalid revision, or a validated one that was never activated.
func editableRevision(revision Revision) bool {
	switch revision.storedState {
	case StateDraft, StateInvalid:
		return true
	case StateValid:
		return revision.ActivatedAt == nil
	default:
		return false
	}
}

func recordEdit(
	ctx context.Context,
	tx pgx.Tx,
	organizationID, revisionID string,
	version int64,
	kind, adminUserID string,
	at time.Time,
	from, to json.RawMessage,
) error {
	changes := make([]PlanChange, 0)
	if len(from) != 0 {
		diff, err := structuralDiff(from, to)
		if err != nil {
			return err
		}
		changes = diff
	}
	count := len(changes)
	if len(changes) > maximumRecordedEditChanges {
		changes = changes[:maximumRecordedEditChanges]
	}
	encoded, err := json.Marshal(changes)
	if err != nil {
		return fmt.Errorf("encode configuration edit: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO config_revision_edits (
			organization_id, config_revision_id, edit_version, kind, admin_user_id,
			edited_at, change_count, changes
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, organizationID, revisionID, version, kind, adminUserID, at, count, encoded); err != nil {
		return mapDatabaseError("record configuration edit", err)
	}
	return nil
}

// ListRevisionEdits returns the newest recorded edits of one revision.
func (store *Store) ListRevisionEdits(ctx context.Context, principal adminauth.Principal, revisionID string) (RevisionEdits, error) {
	if id.Validate(revisionID, id.ConfigRevision) != nil {
		return RevisionEdits{}, ErrInvalid
	}
	revision, err := store.revision(ctx, store.pool, principal.OrganizationID, revisionID, false)
	if err != nil {
		return RevisionEdits{}, err
	}
	if err := store.ensureHistoryEnvironment(ctx, principal.OrganizationID, revision.EnvironmentID); err != nil {
		return RevisionEdits{}, err
	}
	rows, err := store.pool.Query(ctx, `
		SELECT edit_version, kind, edited_at, admin_user_id, change_count, changes
		FROM config_revision_edits
		WHERE organization_id = $1 AND config_revision_id = $2
		ORDER BY edit_version DESC
		LIMIT $3
	`, principal.OrganizationID, revisionID, maximumListedEdits+1)
	if err != nil {
		return RevisionEdits{}, fmt.Errorf("list configuration edits: %w", err)
	}
	defer rows.Close()
	result := RevisionEdits{RevisionID: revisionID, Items: make([]RevisionEdit, 0)}
	for rows.Next() {
		var edit RevisionEdit
		var changes []byte
		if err := rows.Scan(&edit.Version, &edit.Kind, &edit.EditedAt, &edit.EditedBy, &edit.ChangeCount, &changes); err != nil {
			return RevisionEdits{}, fmt.Errorf("scan configuration edit: %w", err)
		}
		if err := json.Unmarshal(changes, &edit.Changes); err != nil {
			return RevisionEdits{}, fmt.Errorf("decode configuration edit: %w", err)
		}
		edit.EditedAt = edit.EditedAt.UTC()
		result.Items = append(result.Items, edit)
	}
	if err := rows.Err(); err != nil {
		return RevisionEdits{}, fmt.Errorf("iterate configuration edits: %w", err)
	}
	if len(result.Items) > maximumListedEdits {
		result.Items, result.Truncated = result.Items[:maximumListedEdits], true
	}
	return result, nil
}

// DiscardRevision tombstones a never-activated draft. The revision stays in
// history with its document; it can no longer be edited, validated,
// simulated or activated.
func (store *Store) DiscardRevision(ctx context.Context, principal adminauth.Principal, revisionID, ifMatch string) (Revision, error) {
	if !canWrite(principal) {
		return Revision{}, ErrForbidden
	}
	if id.Validate(revisionID, id.ConfigRevision) != nil {
		return Revision{}, ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Revision{}, fmt.Errorf("begin configuration discard: %w", err)
	}
	defer rollback(tx)
	revision, err := store.revision(ctx, tx, principal.OrganizationID, revisionID, true)
	if err != nil {
		return Revision{}, err
	}
	if !canWriteIn(principal, revision.applicationID) {
		return Revision{}, ErrForbidden
	}
	if _, _, err := store.environment(ctx, tx, principal.OrganizationID, revision.EnvironmentID, true); err != nil {
		return Revision{}, err
	}
	if !editableRevision(revision) {
		return Revision{}, ErrConflict
	}
	if revision.ETag != ifMatch {
		return Revision{}, ErrETagMismatch
	}
	now := store.now().UTC()
	if _, err := tx.Exec(ctx, `
		UPDATE config_revisions
		SET status = 'discarded', compiled_document = NULL, validated_at = NULL,
			discarded_at = $2, discarded_by_admin_user_id = $3
		WHERE config_revision_id = $1
	`, revisionID, now, principal.AdminUserID); err != nil {
		return Revision{}, mapDatabaseError("discard configuration draft", err)
	}
	if err := store.audit(ctx, tx, principal, revision.organizationID, revision.EnvironmentID,
		"admin.configuration_revision_discard", revisionID,
		[]auditField{{name: "status"}}); err != nil {
		return Revision{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Revision{}, mapDatabaseError("commit configuration discard", err)
	}
	revision.State, revision.storedState = StateDiscarded, StateDiscarded
	revision.compiled = nil
	revision.DiscardedAt, revision.DiscardedBy = &now, principal.AdminUserID
	return revision, nil
}

// mergeInputs loads the draft, the revision it started from and the live
// revision. A draft created before anything was live has no base.
func (store *Store) mergeInputs(ctx context.Context, query databaseQuery, principal adminauth.Principal, draft Revision, activeRevisionID string) (json.RawMessage, Revision, error) {
	if activeRevisionID == "" {
		return nil, Revision{}, ErrNotFound
	}
	live, err := store.revision(ctx, query, principal.OrganizationID, activeRevisionID, false)
	if err != nil {
		return nil, Revision{}, err
	}
	var base json.RawMessage
	if draft.BaseRevisionID != "" {
		baseRevision, err := store.revision(ctx, query, principal.OrganizationID, draft.BaseRevisionID, false)
		if err != nil {
			return nil, Revision{}, err
		}
		base = baseRevision.Document
	}
	return base, live, nil
}

// RebasePreview shows what bringing a stale draft up to date with the live
// revision would combine, by path only.
func (store *Store) RebasePreview(ctx context.Context, principal adminauth.Principal, revisionID string) (MergePreview, error) {
	if !canWrite(principal) {
		return MergePreview{}, ErrForbidden
	}
	if id.Validate(revisionID, id.ConfigRevision) != nil {
		return MergePreview{}, ErrInvalid
	}
	draft, err := store.revision(ctx, store.pool, principal.OrganizationID, revisionID, false)
	if err != nil {
		return MergePreview{}, err
	}
	if !canWriteIn(principal, draft.applicationID) {
		return MergePreview{}, ErrForbidden
	}
	_, activeRevisionID, err := store.environment(ctx, store.pool, principal.OrganizationID, draft.EnvironmentID, false)
	if err != nil {
		return MergePreview{}, err
	}
	if !editableRevision(draft) {
		return MergePreview{}, ErrConflict
	}
	base, live, err := store.mergeInputs(ctx, store.pool, principal, draft, activeRevisionID)
	if err != nil {
		return MergePreview{}, err
	}
	preview := MergePreview{
		RevisionID: draft.ID, BaseRevisionID: draft.BaseRevisionID, LiveRevisionID: live.ID,
		UpToDate: draft.BaseRevisionID == live.ID, DraftChanges: make([]PlanChange, 0),
		LiveChanges: make([]PlanChange, 0), Conflicts: make([]string, 0),
	}
	if preview.UpToDate {
		return preview, nil
	}
	if len(base) != 0 {
		if preview.DraftChanges, err = structuralDiff(base, draft.Document); err != nil {
			return MergePreview{}, err
		}
		if preview.LiveChanges, err = structuralDiff(base, live.Document); err != nil {
			return MergePreview{}, err
		}
	}
	if _, conflicts, err := threeWayMerge(base, draft.Document, live.Document, nil); err != nil {
		return MergePreview{}, err
	} else if conflicts != nil {
		preview.Conflicts = conflicts
	}
	return preview, nil
}

// Rebase brings a stale draft up to date with the live revision. liveRevisionID
// must still be live, and resolutions must name a side for every conflict
// and nothing else. The draft returns to draft state on its new base.
func (store *Store) Rebase(
	ctx context.Context,
	principal adminauth.Principal,
	revisionID, ifMatch, liveRevisionID string,
	resolutions map[string]string,
) (Revision, error) {
	if !canWrite(principal) {
		return Revision{}, ErrForbidden
	}
	if id.Validate(revisionID, id.ConfigRevision) != nil || id.Validate(liveRevisionID, id.ConfigRevision) != nil ||
		len(resolutions) > 1_000 {
		return Revision{}, ErrInvalid
	}
	for path, side := range resolutions {
		if !strings.HasPrefix(path, "/") || len(path) > 1_024 || (side != MergeTakeDraft && side != MergeTakeLive) {
			return Revision{}, ErrInvalid
		}
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Revision{}, fmt.Errorf("begin configuration rebase: %w", err)
	}
	defer rollback(tx)
	draft, err := store.revision(ctx, tx, principal.OrganizationID, revisionID, true)
	if err != nil {
		return Revision{}, err
	}
	if !canWriteIn(principal, draft.applicationID) {
		return Revision{}, ErrForbidden
	}
	_, activeRevisionID, err := store.environment(ctx, tx, principal.OrganizationID, draft.EnvironmentID, true)
	if err != nil {
		return Revision{}, err
	}
	if !editableRevision(draft) || activeRevisionID != liveRevisionID {
		return Revision{}, ErrConflict
	}
	if draft.ETag != ifMatch {
		return Revision{}, ErrETagMismatch
	}
	if draft.BaseRevisionID == liveRevisionID {
		if len(resolutions) != 0 {
			return Revision{}, ErrInvalid
		}
		return draft, nil
	}
	base, live, err := store.mergeInputs(ctx, tx, principal, draft, activeRevisionID)
	if err != nil {
		return Revision{}, err
	}
	merged, conflicts, err := threeWayMerge(base, draft.Document, live.Document, resolutions)
	if err != nil {
		return Revision{}, err
	}
	if len(conflicts) != 0 {
		return Revision{}, ErrMergeConflict
	}
	canonical, err := canonicalDocument(merged)
	if err != nil {
		return Revision{}, err
	}
	if issues := store.validator.SchemaIssues(canonical); len(issues) != 0 {
		return Revision{}, &ValidationFailure{Issues: issues}
	}
	editVersion := draft.editVersion + 1
	etag := revisionETag(revisionID, editVersion, canonical)
	now := store.now().UTC()
	if _, err := tx.Exec(ctx, `
		UPDATE config_revisions
		SET document = $2, etag = $3, edit_version = $4, status = 'draft',
			base_config_revision_id = $5, compiled_document = NULL, validation_errors = NULL,
			validation_report = NULL, validated_at = NULL
		WHERE config_revision_id = $1
	`, revisionID, canonical, etag, editVersion, liveRevisionID); err != nil {
		return Revision{}, mapDatabaseError("rebase configuration draft", err)
	}
	if err := recordEdit(ctx, tx, draft.organizationID, revisionID, editVersion, editKindRebased,
		principal.AdminUserID, now, draft.Document, canonical); err != nil {
		return Revision{}, err
	}
	if err := store.audit(ctx, tx, principal, draft.organizationID, draft.EnvironmentID,
		"admin.configuration_revision_rebase", revisionID,
		[]auditField{{name: "document", sensitive: true}, {name: "base_revision_id"}}); err != nil {
		return Revision{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Revision{}, mapDatabaseError("commit configuration rebase", err)
	}
	draft.State, draft.storedState = StateDraft, StateDraft
	draft.Document = append(json.RawMessage(nil), canonical...)
	draft.Validation, draft.compiled = nil, nil
	draft.ETag, draft.editVersion = etag, editVersion
	draft.BaseRevisionID = liveRevisionID
	draft.UpdatedAt, draft.UpdatedBy = now, principal.AdminUserID
	return draft, nil
}

// environmentBoundSections hold values that point at one environment's own
// infrastructure: sign-in projects, app identifiers, origins, base URLs and
// secret references. Promotion keeps the target's entries for these.
var environmentBoundSections = []string{"identityProviders", "attestationPolicies", "componentDefinitions", "upstreams"}

// PromoteInput copies one environment's live configuration into another
// environment of the same application as a new draft.
type PromoteInput struct {
	TargetEnvironmentID string
	SourceEnvironmentID string
	Description         string
}

// Promote creates a draft in the target environment from the source
// environment's live revision. Features, models, plans, pricing, session and
// privacy settings come from the source. For sign-in providers, attestation
// policies, components and AI connections, the target's own entries stay;
// entries only the source has are copied and listed for review, since they
// may point at the source's projects, identifiers, URLs or secrets.
func (store *Store) Promote(ctx context.Context, principal adminauth.Principal, input PromoteInput) (Revision, PromotionReport, error) {
	if !canWrite(principal) {
		return Revision{}, PromotionReport{}, ErrForbidden
	}
	if id.Validate(input.TargetEnvironmentID, id.Environment) != nil ||
		id.Validate(input.SourceEnvironmentID, id.Environment) != nil ||
		input.TargetEnvironmentID == input.SourceEnvironmentID ||
		len(input.Description) > 512 || strings.ContainsRune(input.Description, '\x00') {
		return Revision{}, PromotionReport{}, ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Revision{}, PromotionReport{}, fmt.Errorf("begin configuration promotion: %w", err)
	}
	defer rollback(tx)
	source, sourceActiveID, err := store.environment(ctx, tx, principal.OrganizationID, input.SourceEnvironmentID, false)
	if err != nil {
		return Revision{}, PromotionReport{}, err
	}
	target, targetActiveID, err := store.environment(ctx, tx, principal.OrganizationID, input.TargetEnvironmentID, true)
	if err != nil {
		return Revision{}, PromotionReport{}, err
	}
	if source.ApplicationID != target.ApplicationID {
		return Revision{}, PromotionReport{}, ErrInvalid
	}
	if !canWriteIn(principal, target.ApplicationID) {
		return Revision{}, PromotionReport{}, ErrForbidden
	}
	if sourceActiveID == "" {
		return Revision{}, PromotionReport{}, ErrNotFound
	}
	if pending, err := pendingDraft(ctx, tx, target.EnvironmentID); err != nil {
		return Revision{}, PromotionReport{}, err
	} else if pending {
		return Revision{}, PromotionReport{}, ErrDraftPending
	}
	sourceRevision, err := store.revision(ctx, tx, principal.OrganizationID, sourceActiveID, false)
	if err != nil {
		return Revision{}, PromotionReport{}, err
	}
	var targetDocument json.RawMessage
	if targetActiveID != "" {
		targetRevision, err := store.revision(ctx, tx, principal.OrganizationID, targetActiveID, false)
		if err != nil {
			return Revision{}, PromotionReport{}, err
		}
		targetDocument = targetRevision.Document
	}
	promoted, report, err := promoteDocument(sourceRevision.Document, targetDocument, target)
	if err != nil {
		return Revision{}, PromotionReport{}, err
	}
	report.SourceEnvironmentID, report.SourceRevisionID = source.EnvironmentID, sourceRevision.ID
	document, err := canonicalDocument(promoted)
	if err != nil {
		return Revision{}, PromotionReport{}, err
	}
	if issues := store.validator.SchemaIssues(document); len(issues) != 0 {
		return Revision{}, PromotionReport{}, &ValidationFailure{Issues: issues}
	}
	revisionID, err := id.New(id.ConfigRevision)
	if err != nil {
		return Revision{}, PromotionReport{}, err
	}
	var version int64
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(max(revision_number), 0) + 1 FROM config_revisions WHERE environment_id = $1
	`, target.EnvironmentID).Scan(&version); err != nil {
		return Revision{}, PromotionReport{}, fmt.Errorf("allocate configuration revision number: %w", err)
	}
	editVersion := int64(1)
	etag := revisionETag(revisionID, editVersion, document)
	now := store.now().UTC()
	description := strings.TrimSpace(input.Description)
	if _, err := tx.Exec(ctx, `
		INSERT INTO config_revisions (
			config_revision_id, organization_id, application_id, environment_id,
			revision_number, etag, status, document, created_by_admin_user_id,
			created_at, base_config_revision_id, description, edit_version
		) VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7, $8, $9, NULLIF($10, ''), NULLIF($11, ''), $12)
	`, revisionID, target.OrganizationID, target.ApplicationID, target.EnvironmentID,
		version, etag, document, principal.AdminUserID, now, targetActiveID, description, editVersion); err != nil {
		return Revision{}, PromotionReport{}, mapDatabaseError("insert promoted configuration draft", err)
	}
	if err := recordEdit(ctx, tx, target.OrganizationID, revisionID, editVersion, editKindPromoted,
		principal.AdminUserID, now, targetDocument, document); err != nil {
		return Revision{}, PromotionReport{}, err
	}
	if err := store.audit(ctx, tx, principal, target.OrganizationID, target.EnvironmentID,
		"admin.configuration_promote", revisionID,
		[]auditField{{name: "document", sensitive: true}, {name: "base_revision_id"}, {name: "source_revision_id"}}); err != nil {
		return Revision{}, PromotionReport{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Revision{}, PromotionReport{}, mapDatabaseError("commit configuration promotion", err)
	}
	return Revision{
		ID: revisionID, EnvironmentID: target.EnvironmentID, State: StateDraft, Version: version,
		Document: append(json.RawMessage(nil), document...), CreatedAt: now, CreatedBy: principal.AdminUserID,
		UpdatedAt: now, UpdatedBy: principal.AdminUserID, BaseRevisionID: targetActiveID,
		Description: description, ETag: etag, organizationID: target.OrganizationID,
		applicationID: target.ApplicationID, storedState: StateDraft, editVersion: editVersion,
	}, report, nil
}

// pendingDraft reports whether an environment has a revision that is neither
// activated nor discarded and newer than its live revision: a working draft
// that promotion would silently replace.
func pendingDraft(ctx context.Context, tx pgx.Tx, environmentID string) (bool, error) {
	var pending bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM config_revisions AS revision
			WHERE revision.environment_id = $1
			  AND revision.activated_at IS NULL
			  AND revision.status <> 'discarded'
			  AND revision.revision_number > COALESCE((
			      SELECT live.revision_number
			      FROM active_config_revisions AS active
			      JOIN config_revisions AS live ON live.config_revision_id = active.config_revision_id
			      WHERE active.environment_id = $1
			  ), 0)
		)
	`, environmentID).Scan(&pending); err != nil {
		return false, fmt.Errorf("check pending configuration draft: %w", err)
	}
	return pending, nil
}

func promoteDocument(source, target json.RawMessage, environment EnvironmentDescriptor) (json.RawMessage, PromotionReport, error) {
	report := PromotionReport{Copied: make([]string, 0), Kept: make([]string, 0), Review: make([]string, 0)}
	decodedSource, err := jsonsafe.Decode(source)
	if err != nil {
		return nil, report, ErrInvalid
	}
	sourceDocument, ok := decodedSource.(map[string]any)
	if !ok {
		return nil, report, ErrInvalid
	}
	targetDocument := map[string]any{}
	if len(target) != 0 {
		decodedTarget, err := jsonsafe.Decode(target)
		if err != nil {
			return nil, report, ErrInvalid
		}
		if targetDocument, ok = decodedTarget.(map[string]any); !ok {
			return nil, report, ErrInvalid
		}
	}
	result := make(map[string]any, len(sourceDocument))
	for key, value := range sourceDocument {
		result[key] = value
	}
	metadata, _ := targetDocument["metadata"].(map[string]any)
	if metadata == nil {
		sourceMetadata, _ := sourceDocument["metadata"].(map[string]any)
		metadata = make(map[string]any, len(sourceMetadata))
		for key, value := range sourceMetadata {
			metadata[key] = value
		}
	}
	metadata["organization"] = environment.OrganizationSlug
	metadata["application"] = environment.ApplicationSlug
	metadata["environment"] = environment.EnvironmentSlug
	result["metadata"] = metadata
	report.Kept = append(report.Kept, "/metadata")

	sourceSpec, _ := sourceDocument["spec"].(map[string]any)
	targetSpec, _ := targetDocument["spec"].(map[string]any)
	spec := make(map[string]any, len(sourceSpec))
	for _, key := range sortedSpecKeys(sourceSpec) {
		if !slices.Contains(environmentBoundSections, key) {
			spec[key] = sourceSpec[key]
			report.Copied = append(report.Copied, "/spec/"+pointerToken(key))
		}
	}
	for _, section := range environmentBoundSections {
		sourceItems, sourceHas := sourceSpec[section].([]any)
		targetItems, _ := targetSpec[section].([]any)
		if !sourceHas && len(targetItems) == 0 {
			continue
		}
		targetIndex, targetIndexed := identifierIndex(targetItems)
		sourceIndex, sourceIndexed := identifierIndex(sourceItems)
		if !targetIndexed || !sourceIndexed {
			return nil, report, ErrInvalid
		}
		items := make([]any, 0, len(sourceItems)+len(targetItems))
		for _, item := range identifierOrder(sourceItems) {
			path := "/spec/" + section + "/" + pointerToken(item)
			if kept, exists := targetIndex[item]; exists {
				items = append(items, kept)
				report.Kept = append(report.Kept, path)
				continue
			}
			items = append(items, sourceIndex[item])
			report.Review = append(report.Review, path)
		}
		for _, item := range identifierOrder(targetItems) {
			if _, inSource := sourceIndex[item]; !inSource {
				items = append(items, targetIndex[item])
				report.Kept = append(report.Kept, "/spec/"+section+"/"+pointerToken(item))
			}
		}
		spec[section] = items
	}
	result["spec"] = spec
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, report, ErrInvalid
	}
	return encoded, report, nil
}

func sortedSpecKeys(spec map[string]any) []string {
	keys := make(map[string]struct{}, len(spec))
	for key := range spec {
		keys[key] = struct{}{}
	}
	return sortedMapKeys(keys)
}
