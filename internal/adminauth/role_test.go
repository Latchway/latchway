package adminauth

import (
	"errors"
	"reflect"
	"testing"
)

func TestRoleCapabilityMatrix(t *testing.T) {
	t.Parallel()

	base := AuthorizationContext{}
	promptOwner := AuthorizationContext{PromptBodiesAllowedByPolicy: true}
	promptAdmin := AuthorizationContext{
		PromptBodiesAllowedByPolicy: true,
		AdminPromptBodiesEnabled:    true,
	}
	tests := []struct {
		role       Role
		capability Capability
		context    AuthorizationContext
		want       bool
	}{
		{RoleOwner, ManageOwners, base, true},
		{RoleAdmin, ManageOwners, base, false},
		{RoleOwner, ManageSecrets, base, true},
		{RoleAdmin, ManageSecrets, base, true},
		{RoleOperator, ManageSecrets, base, false},
		{RoleOwner, ActivateConfiguration, base, true},
		{RoleAdmin, ActivateConfiguration, base, true},
		{RoleOperator, RunSelfTests, base, true},
		{RoleViewer, RunSelfTests, base, false},
		{RoleViewer, InspectUsers, base, true},
		{RoleOperator, RevokeInstallations, base, true},
		{RoleViewer, RevokeInstallations, base, false},
		{RoleOwner, ViewPromptBodies, base, false},
		{RoleOwner, ViewPromptBodies, promptOwner, true},
		{RoleAdmin, ViewPromptBodies, promptOwner, false},
		{RoleAdmin, ViewPromptBodies, promptAdmin, true},
		{RoleOperator, ViewPromptBodies, promptAdmin, false},
	}
	for _, test := range tests {
		if got := test.role.Allows(test.capability, test.context); got != test.want {
			t.Errorf("%s.Allows(%s) = %v, want %v", test.role, test.capability, got, test.want)
		}
	}
}

func TestCapabilitySetRestrictsRole(t *testing.T) {
	t.Parallel()

	set, err := NewCapabilitySet(InspectUsers, ManageSecrets, InspectUsers)
	if err != nil {
		t.Fatalf("NewCapabilitySet() error = %v", err)
	}
	if !reflect.DeepEqual(set.Values(), []Capability{InspectUsers, ManageSecrets}) {
		t.Fatalf("Values() = %v", set.Values())
	}
	if !set.Allows(RoleAdmin, ManageSecrets, AuthorizationContext{}) {
		t.Fatal("scoped admin should manage secrets")
	}
	if set.Allows(RoleViewer, ManageSecrets, AuthorizationContext{}) {
		t.Fatal("scope must not elevate viewer role")
	}
	if set.Allows(RoleAdmin, RunSelfTests, AuthorizationContext{}) {
		t.Fatal("missing scope allowed capability")
	}
}

func TestRoleAndScopeValidation(t *testing.T) {
	t.Parallel()

	if err := Role("superuser").Validate(); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("Role.Validate() error = %v", err)
	}
	if err := Capability("delete_everything").Validate(); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("Capability.Validate() error = %v", err)
	}
	if _, err := NewCapabilitySet(); !errors.Is(err, ErrEmptyTokenScope) {
		t.Fatalf("NewCapabilitySet(empty) error = %v", err)
	}
	if _, err := NewCapabilitySet(Capability("unknown")); !errors.Is(err, ErrInvalidCapability) {
		t.Fatalf("NewCapabilitySet(unknown) error = %v", err)
	}
}
