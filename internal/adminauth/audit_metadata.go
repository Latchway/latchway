package adminauth

import (
	"context"
	"errors"
	"strings"
)

// AuditSource is bounded client attribution for an administrative mutation.
// It is descriptive rather than an authorization input.
type AuditSource string

const (
	AuditSourceConsole AuditSource = "console"
	AuditSourceCLI     AuditSource = "cli"
	AuditSourceAPI     AuditSource = "api"
	AuditSourceSystem  AuditSource = "system"
)

type auditMetadata struct {
	source AuditSource
	reason string
	// resolved is set only after the Admin API authenticates the transport.
	// The source header is not itself an authentication signal.
	resolved bool
}

type auditMetadataContextKey struct{}

// WithAuditMetadata captures a bounded client source claim and a redaction-safe
// reason. The claim is descriptive and must be resolved against the
// authenticated transport before it can distinguish Console from API traffic.
func WithAuditMetadata(ctx context.Context, source AuditSource, reason string) (context.Context, error) {
	if ctx == nil || !validExternalAuditSource(source) {
		return nil, ErrInvalidAuditMutation
	}
	reason = strings.TrimSpace(reason)
	if reason != "" && !validAuditReason(reason) {
		return nil, ErrInvalidAuditMutation
	}
	return context.WithValue(ctx, auditMetadataContextKey{}, auditMetadata{source: source, reason: reason}), nil
}

// ResolveAuditMetadata binds the descriptive source claim to an authenticated
// transport. Session mutations are always Console mutations. API-token callers
// may self-identify as CLI; every other API-token claim is recorded as API.
// Neither CLI nor API is an authorization or cryptographic identity.
func ResolveAuditMetadata(ctx context.Context, method AuthenticationMethod) (context.Context, error) {
	if ctx == nil {
		return nil, ErrInvalidAuditMutation
	}
	metadata, _ := ctx.Value(auditMetadataContextKey{}).(auditMetadata)
	if metadata.reason != "" && !validAuditReason(metadata.reason) {
		return nil, ErrInvalidAuditMutation
	}
	switch method {
	case AuthenticationSession:
		metadata.source = AuditSourceConsole
	case AuthenticationAPIToken:
		if metadata.source != AuditSourceCLI {
			metadata.source = AuditSourceAPI
		}
	default:
		return nil, ErrInvalidAuditMutation
	}
	metadata.resolved = true
	return context.WithValue(ctx, auditMetadataContextKey{}, metadata), nil
}

func auditMetadataFromContext(ctx context.Context, actor AuditActor) auditMetadata {
	if actor.Kind() == AuditActorSystem {
		return auditMetadata{source: AuditSourceSystem}
	}
	if ctx != nil {
		if metadata, ok := ctx.Value(auditMetadataContextKey{}).(auditMetadata); ok &&
			(metadata.reason == "" || validAuditReason(metadata.reason)) {
			if metadata.resolved && validExternalAuditSource(metadata.source) {
				return metadata
			}
			return auditMetadata{source: AuditSourceAPI, reason: metadata.reason, resolved: true}
		}
	}
	return auditMetadata{source: AuditSourceAPI, resolved: true}
}

func validExternalAuditSource(source AuditSource) bool {
	switch source {
	case AuditSourceConsole, AuditSourceCLI, AuditSourceAPI:
		return true
	default:
		return false
	}
}

func validAuditReason(value string) bool {
	if len(value) == 0 || len(value) > 100 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') &&
			(character < '0' || character > '9') &&
			character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	normalized := strings.ReplaceAll(value, ".", "_")
	for _, keyword := range []string{
		"password", "secret", "token", "credential", "authorization", "cookie",
		"private_key", "ciphertext", "proof", "evidence",
	} {
		if strings.Contains(normalized, keyword) {
			return false
		}
	}
	return true
}

// ValidateAuditReason allows API and CLI parsing to reject unsafe reason
// codes before beginning a transaction.
func ValidateAuditReason(value string) error {
	if value == "" || validAuditReason(value) {
		return nil
	}
	return errors.New("audit reason must be a stable redaction-safe code")
}
