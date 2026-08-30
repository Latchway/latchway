package adminauth

import (
	"errors"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

func TestNormalizeEmail(t *testing.T) {
	t.Parallel()

	got, err := NormalizeEmail("  Owner@Example.COM ")
	if err != nil {
		t.Fatalf("NormalizeEmail() error = %v", err)
	}
	if got != "owner@example.com" {
		t.Fatalf("NormalizeEmail() = %q", got)
	}
	for _, invalid := range []string{"", "owner", "@example.com", "owner@", "a@b@c", "a\n@example.com"} {
		if _, err := NormalizeEmail(invalid); !errors.Is(err, ErrInvalidAdminInput) {
			t.Errorf("NormalizeEmail(%q) error = %v", invalid, err)
		}
	}
}

func TestCreateSessionInputBounds(t *testing.T) {
	t.Parallel()

	valid := CreateSessionInput{
		OrganizationID: mustIdentifier(t, id.Organization),
		AdminUserID:    mustIdentifier(t, id.AdminUser),
		Lifetime:       time.Hour,
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("validate() error = %v", err)
	}
	tooShort := valid
	tooShort.Lifetime = time.Minute
	if err := tooShort.validate(); !errors.Is(err, ErrInvalidAdminInput) {
		t.Fatalf("short lifetime error = %v", err)
	}
	tooLong := valid
	tooLong.Lifetime = 31 * 24 * time.Hour
	if err := tooLong.validate(); !errors.Is(err, ErrInvalidAdminInput) {
		t.Fatalf("long lifetime error = %v", err)
	}
}

func TestPrincipalAPITokenScopeCannotElevateRole(t *testing.T) {
	t.Parallel()

	scope, err := NewCapabilitySet(ManageSecrets, InspectUsers)
	if err != nil {
		t.Fatalf("NewCapabilitySet() error = %v", err)
	}
	principal := Principal{
		Role:   RoleViewer,
		Method: AuthenticationAPIToken,
		scope:  &scope,
	}
	if principal.Allows(ManageSecrets, AuthorizationContext{}) {
		t.Fatal("API scope elevated viewer role")
	}
	if !principal.Allows(InspectUsers, AuthorizationContext{}) {
		t.Fatal("viewer lost in-scope inspect capability")
	}
}
