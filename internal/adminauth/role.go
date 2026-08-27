package adminauth

import (
	"errors"
	"fmt"
	"slices"
)

var (
	// ErrInvalidRole indicates an unknown administrative role.
	ErrInvalidRole = errors.New("invalid admin role")
	// ErrInvalidCapability indicates an unknown authorization capability.
	ErrInvalidCapability = errors.New("invalid admin capability")
	// ErrEmptyTokenScope enforces scoped administrative API tokens.
	ErrEmptyTokenScope = errors.New("admin API token requires at least one capability")
)

// Role is an organization-scoped administrative role.
type Role string

const (
	RoleOwner    Role = "owner"
	RoleAdmin    Role = "admin"
	RoleOperator Role = "operator"
	RoleViewer   Role = "viewer"
)

// Capability is a stable authorization operation.
type Capability string

const (
	ManageOwners          Capability = "manage_owners"
	ManageSecrets         Capability = "manage_secrets"
	ActivateConfiguration Capability = "activate_configuration"
	RunSelfTests          Capability = "run_self_tests"
	InspectUsers          Capability = "inspect_users"
	RevokeInstallations   Capability = "revoke_installations"
	ViewPromptBodies      Capability = "view_prompt_bodies"
)

var knownCapabilities = []Capability{
	ManageOwners,
	ManageSecrets,
	ActivateConfiguration,
	RunSelfTests,
	InspectUsers,
	RevokeInstallations,
	ViewPromptBodies,
}

// Validate confirms that role is supported.
func (role Role) Validate() error {
	switch role {
	case RoleOwner, RoleAdmin, RoleOperator, RoleViewer:
		return nil
	default:
		return ErrInvalidRole
	}
}

// Validate confirms that capability is supported.
func (capability Capability) Validate() error {
	if slices.Contains(knownCapabilities, capability) {
		return nil
	}
	return ErrInvalidCapability
}

// AuthorizationContext supplies the policy gates that cannot be represented
// by a static role matrix.
type AuthorizationContext struct {
	PromptBodiesAllowedByPolicy bool
	AdminPromptBodiesEnabled    bool
}

// Allows evaluates the built-in role matrix and conditional prompt-body gate.
func (role Role) Allows(capability Capability, context AuthorizationContext) bool {
	if role.Validate() != nil || capability.Validate() != nil {
		return false
	}
	switch capability {
	case ManageOwners:
		return role == RoleOwner
	case ManageSecrets, ActivateConfiguration:
		return role == RoleOwner || role == RoleAdmin
	case RunSelfTests, RevokeInstallations:
		return role == RoleOwner || role == RoleAdmin || role == RoleOperator
	case InspectUsers:
		return true
	case ViewPromptBodies:
		if !context.PromptBodiesAllowedByPolicy {
			return false
		}
		return role == RoleOwner || (role == RoleAdmin && context.AdminPromptBodiesEnabled)
	default:
		return false
	}
}

// CapabilitySet is a validated API-token scope.
type CapabilitySet struct {
	values map[Capability]struct{}
}

// NewCapabilitySet constructs a non-empty, duplicate-free token scope.
func NewCapabilitySet(capabilities ...Capability) (CapabilitySet, error) {
	if len(capabilities) == 0 {
		return CapabilitySet{}, ErrEmptyTokenScope
	}
	values := make(map[Capability]struct{}, len(capabilities))
	for _, capability := range capabilities {
		if err := capability.Validate(); err != nil {
			return CapabilitySet{}, fmt.Errorf("%w: %q", err, capability)
		}
		values[capability] = struct{}{}
	}
	return CapabilitySet{values: values}, nil
}

// Values returns a sorted defensive copy for persistence.
func (set CapabilitySet) Values() []Capability {
	values := make([]Capability, 0, len(set.values))
	for capability := range set.values {
		values = append(values, capability)
	}
	slices.Sort(values)
	return values
}

// Allows ensures an API token cannot exceed either its scope or its member
// role.
func (set CapabilitySet) Allows(role Role, capability Capability, context AuthorizationContext) bool {
	if _, ok := set.values[capability]; !ok {
		return false
	}
	return role.Allows(capability, context)
}
