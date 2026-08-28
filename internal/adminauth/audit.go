package adminauth

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/id"
)

var (
	// ErrInvalidAuditMutation indicates malformed or unsafe audit input.
	ErrInvalidAuditMutation = errors.New("invalid audit mutation")
	// ErrSensitiveAuditField indicates that a sensitive field was incorrectly
	// classified as public.
	ErrSensitiveAuditField = errors.New("sensitive audit field requires redaction")
)

// AuditActorKind identifies the authenticated principal behind a mutation.
type AuditActorKind string

const (
	AuditActorAdminUser AuditActorKind = "admin_user"
	AuditActorAPIToken  AuditActorKind = "admin_api_token"
	AuditActorSystem    AuditActorKind = "system"
)

// AuditOutcome records the mutation result without a free-form error payload.
type AuditOutcome string

const (
	AuditSucceeded AuditOutcome = "succeeded"
	AuditDenied    AuditOutcome = "denied"
	AuditFailed    AuditOutcome = "failed"
	// AuditIndeterminate means the database commit acknowledgement was lost,
	// so the caller cannot truthfully assert either success or failure.
	AuditIndeterminate AuditOutcome = "indeterminate"
)

// AuditOperation describes how a field changed without recording its value.
type AuditOperation string

const (
	AuditSet     AuditOperation = "set"
	AuditClear   AuditOperation = "clear"
	AuditAdd     AuditOperation = "add"
	AuditRemove  AuditOperation = "remove"
	AuditRotate  AuditOperation = "rotate"
	AuditConsume AuditOperation = "consume"
	AuditRevoke  AuditOperation = "revoke"
)

// AuditClassification indicates whether the changed field is sensitive. Audit
// changes never carry before or after values in either classification.
type AuditClassification string

const (
	AuditPublic    AuditClassification = "public"
	AuditSensitive AuditClassification = "sensitive"
)

// AuditActor is a validated actor reference.
type AuditActor struct {
	kind AuditActorKind
	id   string
}

// NewAdminUserActor constructs an administrator actor.
func NewAdminUserActor(adminUserID string) (AuditActor, error) {
	if err := id.Validate(adminUserID, id.AdminUser); err != nil {
		return AuditActor{}, fmt.Errorf("%w: admin user actor: %v", ErrInvalidAuditMutation, err)
	}
	return AuditActor{kind: AuditActorAdminUser, id: adminUserID}, nil
}

// NewAPITokenActor constructs an API-token actor.
func NewAPITokenActor(tokenID string) (AuditActor, error) {
	if err := id.Validate(tokenID, id.AdminAPIToken); err != nil {
		return AuditActor{}, fmt.Errorf("%w: API token actor: %v", ErrInvalidAuditMutation, err)
	}
	return AuditActor{kind: AuditActorAPIToken, id: tokenID}, nil
}

// SystemActor constructs the internal system actor.
func SystemActor() AuditActor {
	return AuditActor{kind: AuditActorSystem}
}

// Kind returns the actor kind for persistence.
func (actor AuditActor) Kind() AuditActorKind {
	return actor.kind
}

// ID returns the opaque actor ID, empty only for the system actor.
func (actor AuditActor) ID() string {
	return actor.id
}

func (actor AuditActor) validate() error {
	switch actor.kind {
	case AuditActorAdminUser:
		return id.Validate(actor.id, id.AdminUser)
	case AuditActorAPIToken:
		return id.Validate(actor.id, id.AdminAPIToken)
	case AuditActorSystem:
		if actor.id != "" {
			return ErrInvalidAuditMutation
		}
		return nil
	default:
		return ErrInvalidAuditMutation
	}
}

// AuditChange records only the field, operation, and classification. Omitting
// values entirely makes plaintext credential leakage structurally impossible.
type AuditChange struct {
	field          string
	operation      AuditOperation
	classification AuditClassification
}

// NewPublicAuditChange constructs a non-sensitive field marker.
func NewPublicAuditChange(field string, operation AuditOperation) (AuditChange, error) {
	if err := validateAuditField(field); err != nil {
		return AuditChange{}, err
	}
	if isSensitiveAuditField(field) {
		return AuditChange{}, ErrSensitiveAuditField
	}
	if err := validateAuditOperation(operation); err != nil {
		return AuditChange{}, err
	}
	return AuditChange{field: field, operation: operation, classification: AuditPublic}, nil
}

// NewSensitiveAuditChange constructs a redacted sensitive-field marker.
func NewSensitiveAuditChange(field string, operation AuditOperation) (AuditChange, error) {
	if err := validateAuditField(field); err != nil {
		return AuditChange{}, err
	}
	if err := validateAuditOperation(operation); err != nil {
		return AuditChange{}, err
	}
	return AuditChange{field: field, operation: operation, classification: AuditSensitive}, nil
}

// Field returns the changed field name.
func (change AuditChange) Field() string {
	return change.field
}

// Operation returns the value-free mutation operation.
func (change AuditChange) Operation() AuditOperation {
	return change.operation
}

// Classification returns the field's redaction class.
func (change AuditChange) Classification() AuditClassification {
	return change.classification
}

func (change AuditChange) validate() error {
	if err := validateAuditField(change.field); err != nil {
		return err
	}
	if err := validateAuditOperation(change.operation); err != nil {
		return err
	}
	switch change.classification {
	case AuditPublic:
		if isSensitiveAuditField(change.field) {
			return ErrSensitiveAuditField
		}
	case AuditSensitive:
	default:
		return ErrInvalidAuditMutation
	}
	return nil
}

// AuditMutation is the complete value-safe event written with an
// administrative mutation.
type AuditMutation struct {
	eventID        string
	organizationID string
	environmentID  string
	actor          AuditActor
	action         string
	resourceType   string
	resourceID     string
	outcome        AuditOutcome
	requestID      string
	occurredAt     time.Time
	changes        []AuditChange
}

// NewAuditMutation validates and defensively copies an audit event.
func NewAuditMutation(
	eventID string,
	organizationID string,
	environmentID string,
	actor AuditActor,
	action string,
	resourceType string,
	resourceID string,
	outcome AuditOutcome,
	requestID string,
	occurredAt time.Time,
	changes []AuditChange,
) (AuditMutation, error) {
	if err := id.Validate(eventID, id.AuditEvent); err != nil {
		return AuditMutation{}, fmt.Errorf("%w: event ID: %v", ErrInvalidAuditMutation, err)
	}
	if organizationID != "" {
		if err := id.Validate(organizationID, id.Organization); err != nil {
			return AuditMutation{}, fmt.Errorf("%w: organization ID: %v", ErrInvalidAuditMutation, err)
		}
	}
	if environmentID != "" {
		if organizationID == "" {
			return AuditMutation{}, fmt.Errorf("%w: environment requires organization", ErrInvalidAuditMutation)
		}
		if err := id.Validate(environmentID, id.Environment); err != nil {
			return AuditMutation{}, fmt.Errorf("%w: environment ID: %v", ErrInvalidAuditMutation, err)
		}
	}
	if err := actor.validate(); err != nil {
		return AuditMutation{}, fmt.Errorf("%w: actor", ErrInvalidAuditMutation)
	}
	if !isAuditName(action, 100) || !isAuditName(resourceType, 64) {
		return AuditMutation{}, fmt.Errorf("%w: action or resource type", ErrInvalidAuditMutation)
	}
	if _, err := id.Parse(resourceID); err != nil {
		return AuditMutation{}, fmt.Errorf("%w: resource ID", ErrInvalidAuditMutation)
	}
	switch outcome {
	case AuditSucceeded, AuditDenied, AuditFailed, AuditIndeterminate:
	default:
		return AuditMutation{}, fmt.Errorf("%w: outcome", ErrInvalidAuditMutation)
	}
	if err := validateRequestID(requestID); err != nil {
		return AuditMutation{}, fmt.Errorf("%w: request ID", ErrInvalidAuditMutation)
	}
	if occurredAt.IsZero() {
		return AuditMutation{}, fmt.Errorf("%w: occurrence time", ErrInvalidAuditMutation)
	}
	if len(changes) == 0 || len(changes) > 100 {
		return AuditMutation{}, fmt.Errorf("%w: changes", ErrInvalidAuditMutation)
	}
	safeChanges := make([]AuditChange, len(changes))
	copy(safeChanges, changes)
	for _, change := range safeChanges {
		if err := change.validate(); err != nil {
			return AuditMutation{}, err
		}
	}

	return AuditMutation{
		eventID:        eventID,
		organizationID: organizationID,
		environmentID:  environmentID,
		actor:          actor,
		action:         action,
		resourceType:   resourceType,
		resourceID:     resourceID,
		outcome:        outcome,
		requestID:      requestID,
		occurredAt:     occurredAt.UTC(),
		changes:        safeChanges,
	}, nil
}

func validateRequestID(value string) error {
	if value == "" {
		return nil
	}
	return id.Validate(value, id.AdminRequest)
}

// EventID returns the audit event ID.
func (mutation AuditMutation) EventID() string { return mutation.eventID }

// OrganizationID returns the optional tenant ID.
func (mutation AuditMutation) OrganizationID() string { return mutation.organizationID }

// EnvironmentID returns the optional environment ID.
func (mutation AuditMutation) EnvironmentID() string { return mutation.environmentID }

// Actor returns the validated actor.
func (mutation AuditMutation) Actor() AuditActor { return mutation.actor }

// Action returns the stable action name.
func (mutation AuditMutation) Action() string { return mutation.action }

// ResourceType returns the stable resource type.
func (mutation AuditMutation) ResourceType() string { return mutation.resourceType }

// ResourceID returns the opaque resource identifier.
func (mutation AuditMutation) ResourceID() string { return mutation.resourceID }

// Outcome returns the mutation result.
func (mutation AuditMutation) Outcome() AuditOutcome { return mutation.outcome }

// RequestID returns the optional correlation ID.
func (mutation AuditMutation) RequestID() string { return mutation.requestID }

// OccurredAt returns the normalized UTC time.
func (mutation AuditMutation) OccurredAt() time.Time { return mutation.occurredAt }

// Changes returns a defensive copy.
func (mutation AuditMutation) Changes() []AuditChange {
	changes := make([]AuditChange, len(mutation.changes))
	copy(changes, mutation.changes)
	return changes
}

func validateAuditOperation(operation AuditOperation) error {
	switch operation {
	case AuditSet, AuditClear, AuditAdd, AuditRemove, AuditRotate, AuditConsume, AuditRevoke:
		return nil
	default:
		return ErrInvalidAuditMutation
	}
}

func validateAuditField(field string) error {
	if !isAuditName(field, 64) {
		return ErrInvalidAuditMutation
	}
	return nil
}

func isAuditName(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for index := range value {
		character := value[index]
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '_' && character != '.' {
			return false
		}
		if index == 0 && character >= '0' && character <= '9' {
			return false
		}
	}
	return true
}

func isSensitiveAuditField(field string) bool {
	normalized := strings.ReplaceAll(field, ".", "_")
	keywords := []string{
		"password",
		"secret",
		"token",
		"credential",
		"authorization",
		"cookie",
		"private_key",
		"ciphertext",
		"nonce",
		"proof",
		"evidence",
	}
	for _, keyword := range keywords {
		if strings.Contains(normalized, keyword) {
			return true
		}
	}
	return false
}
