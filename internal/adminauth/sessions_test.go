package adminauth

import (
	"errors"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

func TestAdminSessionPageRequestValidation(t *testing.T) {
	t.Parallel()

	instant := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	sessionID := id.Must(id.AdminSession)
	valid := []AdminSessionPageRequest{
		{Size: 1},
		{Size: 200},
		{After: instant, AfterID: sessionID, Size: 50},
	}
	for _, page := range valid {
		if err := page.validate(); err != nil {
			t.Fatalf("validate(%+v) error = %v", page, err)
		}
	}
	invalid := []AdminSessionPageRequest{
		{},
		{Size: 201},
		{After: instant, Size: 50},
		{AfterID: sessionID, Size: 50},
		{After: instant, AfterID: id.Must(id.AdminUser), Size: 50},
	}
	for _, page := range invalid {
		if err := page.validate(); !errors.Is(err, ErrInvalidAdminInput) {
			t.Fatalf("validate(%+v) error = %v, want ErrInvalidAdminInput", page, err)
		}
	}
}

func TestCurrentAdminSessionIDRejectsUnknownOrMalformedPrincipal(t *testing.T) {
	t.Parallel()

	sessionID := id.Must(id.AdminSession)
	if current, err := currentAdminSessionID(Principal{Method: AuthenticationSession, CredentialID: sessionID}); err != nil || current != sessionID {
		t.Fatalf("currentAdminSessionID(session) = %q, %v", current, err)
	}
	if current, err := currentAdminSessionID(Principal{Method: AuthenticationAPIToken, CredentialID: id.Must(id.AdminAPIToken)}); err != nil || current != "" {
		t.Fatalf("currentAdminSessionID(API token) = %q, %v", current, err)
	}
	for _, principal := range []Principal{
		{},
		{Method: AuthenticationSession, CredentialID: id.Must(id.AdminAPIToken)},
		{Method: AuthenticationAPIToken, CredentialID: sessionID},
	} {
		if _, err := currentAdminSessionID(principal); !errors.Is(err, ErrInvalidAdminInput) {
			t.Fatalf("currentAdminSessionID(%+v) error = %v, want ErrInvalidAdminInput", principal, err)
		}
	}
}
