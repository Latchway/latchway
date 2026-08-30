package requestidentity

import (
	"context"
	"errors"
	"testing"

	"github.com/latchway/latchway/internal/id"
)

func TestNewContextGeneratesDistinctCanonicalLogicalIDs(t *testing.T) {
	t.Parallel()

	firstContext, err := NewContext(context.Background())
	if err != nil {
		t.Fatalf("NewContext() first error = %v", err)
	}
	secondContext, err := NewContext(context.Background())
	if err != nil {
		t.Fatalf("NewContext() second error = %v", err)
	}
	first, firstOK := FromContext(firstContext)
	second, secondOK := FromContext(secondContext)
	if !firstOK || !secondOK {
		t.Fatal("generated logical request identity is missing")
	}
	if err := id.Validate(first.String(), id.LogicalRequest); err != nil {
		t.Fatalf("first logical request ID is not canonical: %v", err)
	}
	if err := id.Validate(second.String(), id.LogicalRequest); err != nil {
		t.Fatalf("second logical request ID is not canonical: %v", err)
	}
	if first.String() == second.String() {
		t.Fatalf("logical request IDs were reused: %q", first.String())
	}
}

func TestLogicalIdentitySurvivesDerivedContexts(t *testing.T) {
	t.Parallel()

	requestContext, err := NewContext(context.Background())
	if err != nil {
		t.Fatalf("NewContext() error = %v", err)
	}
	want, ok := FromContext(requestContext)
	if !ok {
		t.Fatal("generated logical request identity is missing")
	}
	derived := context.WithValue(requestContext, struct{ name string }{"downstream"}, "value")
	got, ok := FromContext(derived)
	if !ok || got.String() != want.String() {
		t.Fatalf("derived logical request identity = %q, %t; want %q", got.String(), ok, want.String())
	}
}

func TestNewContextFailsClosedForGeneratorFailuresAndInvalidOutput(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("entropy unavailable")
	if ctx, err := newContext(context.Background(), func() (string, error) {
		return "", sentinel
	}); !errors.Is(err, sentinel) || ctx != nil {
		t.Fatalf("generator failure = (%v, %v), want nil context and sentinel error", ctx, err)
	}
	if ctx, err := newContext(context.Background(), func() (string, error) {
		return "req_client_chosen", nil
	}); err == nil || ctx != nil {
		t.Fatalf("invalid generator output = (%v, %v), want failure", ctx, err)
	}
	if ctx, err := newContext(intentionallyNilContext(), func() (string, error) {
		return "", nil
	}); err == nil || ctx != nil {
		t.Fatalf("nil parent = (%v, %v), want failure", ctx, err)
	}
}

func TestFromContextRejectsMissingIdentity(t *testing.T) {
	t.Parallel()

	if identity, ok := FromContext(context.Background()); ok || identity.String() != "" {
		t.Fatalf("missing identity = %q, %t", identity.String(), ok)
	}
	if identity, ok := FromContext(intentionallyNilContext()); ok || identity.String() != "" {
		t.Fatalf("nil context identity = %q, %t", identity.String(), ok)
	}
}

// intentionallyNilContext preserves adversarial nil-context coverage without
// encouraging nil contexts in production call sites.
func intentionallyNilContext() context.Context { return nil }
