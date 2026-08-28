package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/id"
)

func TestManagerInputBoundsAuthorizationAndClearing(t *testing.T) {
	t.Parallel()
	provider := testEnvironmentMasterKey(t, 0xd1)
	manager := &Manager{managerMaterial: &managerMaterial{
		pool: new(pgxpool.Pool), provider: provider, providerKeyID: provider.KeyID(),
	}}
	principal := adminauth.Principal{
		OrganizationID: mustSecretID(t, id.Organization),
		AdminUserID:    mustSecretID(t, id.AdminUser),
		Role:           adminauth.RoleOwner,
		Method:         adminauth.AuthenticationSession,
	}
	environmentID := mustSecretID(t, id.Environment)
	requestID := mustSecretID(t, id.AdminRequest)

	createTests := []struct {
		name  string
		input CreateInput
	}{
		{name: "empty value", input: CreateInput{EnvironmentID: environmentID, Name: "provider-key", RequestID: requestID}},
		{name: "oversized value", input: CreateInput{EnvironmentID: environmentID, Name: "provider-key", Value: bytes.Repeat([]byte{'x'}, MaxValueBytes+1), RequestID: requestID}},
		{name: "invalid UTF-8 value", input: CreateInput{EnvironmentID: environmentID, Name: "provider-key", Value: []byte{0xff}, RequestID: requestID}},
		{name: "typed name", input: CreateInput{EnvironmentID: environmentID, Name: "secret/provider-key", Value: []byte("sensitive"), RequestID: requestID}},
		{name: "nested name", input: CreateInput{EnvironmentID: environmentID, Name: "provider/key", Value: []byte("sensitive"), RequestID: requestID}},
		{name: "uppercase name", input: CreateInput{EnvironmentID: environmentID, Name: "Provider-Key", Value: []byte("sensitive"), RequestID: requestID}},
		{name: "invalid request ID", input: CreateInput{EnvironmentID: environmentID, Name: "provider-key", Value: []byte("sensitive"), RequestID: environmentID}},
	}
	for _, test := range createTests {
		t.Run(test.name, func(t *testing.T) {
			value := test.input.Value
			if _, err := manager.Create(context.Background(), principal, test.input); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Create() error = %v", err)
			}
			if !allZero(value) {
				t.Fatalf("Create() retained rejected plaintext: %x", value)
			}
		})
	}

	viewer := principal
	viewer.Role = adminauth.RoleViewer
	deniedValue := []byte("denied plaintext")
	if _, err := manager.Create(context.Background(), viewer, CreateInput{
		EnvironmentID: environmentID, Name: "provider-key", Value: deniedValue, RequestID: requestID,
	}); !errors.Is(err, ErrForbidden) {
		t.Fatalf("unauthorized Create() error = %v", err)
	}
	if !allZero(deniedValue) {
		t.Fatalf("unauthorized Create() retained plaintext: %x", deniedValue)
	}

	rotateValue := []byte("invalid rotation plaintext")
	if _, err := manager.Rotate(context.Background(), principal, RotateInput{
		SecretID: environmentID, Value: rotateValue, RequestID: requestID,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid Rotate() error = %v", err)
	}
	if !allZero(rotateValue) {
		t.Fatalf("invalid Rotate() retained plaintext: %x", rotateValue)
	}
}

func TestManagerPageAndNameValidation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 8, 28, 1, 2, 3, 0, time.UTC)
	recordID := mustSecretID(t, id.SecretRecord)
	validPages := []PageRequest{
		{Size: 1},
		{Size: 200},
		{Before: now, BeforeID: recordID, Size: 50},
	}
	for _, page := range validPages {
		if err := page.validate(); err != nil {
			t.Fatalf("valid page %+v: %v", page, err)
		}
	}
	invalidPages := []PageRequest{
		{},
		{Size: 201},
		{Before: now, Size: 1},
		{BeforeID: recordID, Size: 1},
		{Before: now, BeforeID: mustSecretID(t, id.Environment), Size: 1},
	}
	for _, page := range invalidPages {
		if !errors.Is(page.validate(), ErrInvalid) {
			t.Fatalf("invalid page accepted: %+v", page)
		}
	}
	for _, name := range []string{"a", "ab", "provider-key", "provider_key", strings.Repeat("a", 63)} {
		if !validSecretName(name) {
			t.Fatalf("valid secret name rejected: %q", name)
		}
	}
	for _, name := range []string{"", "A", "secret/a", "a.b", "a/b", strings.Repeat("a", 64)} {
		if validSecretName(name) {
			t.Fatalf("invalid secret name accepted: %q", name)
		}
	}
}

func TestSecretValueUsesTheNormativeUTF8ByteBound(t *testing.T) {
	t.Parallel()
	for _, value := range [][]byte{
		[]byte("a"),
		[]byte("é"),
		bytes.Repeat([]byte{'x'}, MaxValueBytes),
	} {
		if !validSecretValue(value) {
			t.Fatalf("valid secret value rejected: byte length=%d", len(value))
		}
	}
	for _, value := range [][]byte{
		nil,
		{},
		{0xff},
		bytes.Repeat([]byte{'x'}, MaxValueBytes+1),
		bytes.Repeat([]byte("é"), (MaxValueBytes/2)+1),
	} {
		if validSecretValue(value) {
			t.Fatalf("invalid secret value accepted: byte length=%d", len(value))
		}
	}
}

func TestManagerFormattingAndJSONNeverExposePlaintext(t *testing.T) {
	t.Parallel()
	plaintext := "manager-unit-plaintext"
	provider := testEnvironmentMasterKey(t, 0xd2)
	manager := &Manager{managerMaterial: &managerMaterial{
		pool: new(pgxpool.Pool), provider: provider, providerKeyID: provider.KeyID(),
	}}
	values := map[string]any{
		"manager pointer": manager,
		"manager value":   *manager,
		"create input": CreateInput{
			EnvironmentID: mustSecretID(t, id.Environment), Name: "provider-key", Value: []byte(plaintext),
		},
		"rotate input": RotateInput{SecretID: mustSecretID(t, id.SecretRecord), Value: []byte(plaintext)},
	}
	for label, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			formatted := fmt.Sprintf(format, value)
			if formatted != "[REDACTED]" || strings.Contains(formatted, plaintext) {
				t.Fatalf("%s format %q = %q", label, format, formatted)
			}
		}
	}
	encoded, err := json.Marshal(CreateInput{
		EnvironmentID: mustSecretID(t, id.Environment), Name: "provider-key", Value: []byte(plaintext),
	})
	if err != nil {
		t.Fatalf("marshal CreateInput: %v", err)
	}
	if bytes.Contains(encoded, []byte(plaintext)) {
		t.Fatalf("CreateInput JSON exposed plaintext: %s", encoded)
	}
}

func TestManagerCommitErrorClassification(t *testing.T) {
	t.Parallel()
	if err := mapManagerCommitError("commit secret test", &pgconn.PgError{Code: "40001"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("serialization commit error = %v", err)
	}
	if err := mapManagerCommitError("commit secret test", pgx.ErrTxCommitRollback); errors.Is(err, ErrIndeterminate) {
		t.Fatalf("definite commit rollback classified indeterminate: %v", err)
	}
	transportDetail := "connection lost at sensitive-db-host.example"
	err := mapManagerCommitError("commit secret test", errors.New(transportDetail))
	if !errors.Is(err, ErrIndeterminate) || strings.Contains(err.Error(), transportDetail) {
		t.Fatalf("ambiguous commit error = %v", err)
	}
}

func TestManagerCollapsesProviderErrors(t *testing.T) {
	t.Parallel()
	plaintext := []byte("provider-error-plaintext")
	provider := leakingEncryptProvider{keyID: "env_safe-key", plaintext: string(plaintext)}
	manager := &Manager{managerMaterial: &managerMaterial{provider: provider, providerKeyID: provider.KeyID()}}
	_, envelope, err := manager.encryptMetadata(secretEnvironment{
		OrganizationID: mustSecretID(t, id.Organization),
		ApplicationID:  mustSecretID(t, id.Application),
		EnvironmentID:  mustSecretID(t, id.Environment),
	}, mustSecretID(t, id.SecretRecord), "provider-key", 1, plaintext, time.Now().UTC())
	if !errors.Is(err, errEncryptionFailed) {
		t.Fatalf("encryptMetadata() error = %v", err)
	}
	if strings.Contains(err.Error(), string(plaintext)) {
		t.Fatalf("provider error exposed plaintext: %v", err)
	}
	if len(envelope.Ciphertext) != 0 || len(envelope.Nonce) != 0 {
		t.Fatalf("failed encryption returned envelope: %+v", envelope)
	}
}

type leakingEncryptProvider struct {
	keyID     string
	plaintext string
}

func (provider leakingEncryptProvider) Encrypt([]byte, AssociatedData) (Envelope, error) {
	return Envelope{Nonce: []byte(provider.plaintext), Ciphertext: []byte(provider.plaintext)},
		errors.New("provider failed around " + provider.plaintext)
}

func (provider leakingEncryptProvider) Decrypt(Envelope, AssociatedData) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (provider leakingEncryptProvider) KeyID() string { return provider.keyID }
