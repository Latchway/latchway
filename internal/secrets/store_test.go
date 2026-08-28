package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/id"
)

func TestStoreUseAuthenticatesAndClearsPlaintext(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	scope := testSecretScope(t)
	provider := testEnvironmentMasterKey(t, 0x41)
	record := testSecretRecord(t, provider, scope, "identity-key", 1, []byte("provider credential"), now)
	loader := &fakeSecretRecordLoader{record: record}
	store, err := newStore(loader, provider, provider.KeyID())
	if err != nil {
		t.Fatalf("construct secret store: %v", err)
	}

	var callbackBuffer []byte
	err = store.Use(context.Background(), scope, "secret/identity-key", func(plaintext []byte) error {
		callbackBuffer = plaintext
		if !bytes.Equal(plaintext, []byte("provider credential")) {
			t.Fatalf("callback plaintext = %q", plaintext)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("use active secret: %v", err)
	}
	if loader.name != "identity-key" || loader.scope != scope {
		t.Fatalf("loader received scope=%+v name=%q", loader.scope, loader.name)
	}
	if len(callbackBuffer) == 0 || !allZero(callbackBuffer) {
		t.Fatalf("callback plaintext buffer was retained after use: %x", callbackBuffer)
	}
}

func TestStoreUseFailsClosedForCryptographicMismatch(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	scope := testSecretScope(t)
	provider := testEnvironmentMasterKey(t, 0x51)
	base := testSecretRecord(t, provider, scope, "identity-key", 3, []byte("never disclose this value"), now)

	tests := []struct {
		name     string
		record   func(*testing.T) secretRecord
		provider func(*testing.T) Provider
	}{
		{
			name: "wrong key identifier",
			record: func(*testing.T) secretRecord {
				record := cloneSecretRecord(base)
				record.masterKeyID = "env_wrong-key"
				return record
			},
			provider: func(*testing.T) Provider { return provider },
		},
		{
			name: "wrong associated data",
			record: func(t *testing.T) secretRecord {
				record := cloneSecretRecord(base)
				wrongID := mustSecretID(t, id.SecretRecord)
				envelope, err := provider.Encrypt([]byte("never disclose this value"), AssociatedData{
					OrganizationID: scope.OrganizationID,
					EnvironmentID:  scope.EnvironmentID,
					SecretID:       wrongID,
					SecretVersion:  record.version,
					FormatVersion:  formatVersion,
				})
				if err != nil {
					t.Fatalf("encrypt wrong-AAD fixture: %v", err)
				}
				record.nonce = envelope.Nonce
				record.ciphertext = envelope.Ciphertext
				return record
			},
			provider: func(*testing.T) Provider { return provider },
		},
		{
			name: "wrong master key",
			record: func(*testing.T) secretRecord {
				return cloneSecretRecord(base)
			},
			provider: func(t *testing.T) Provider {
				return providerKeyIDOverride{Provider: testEnvironmentMasterKey(t, 0x52), keyID: provider.KeyID()}
			},
		},
		{
			name: "tampered ciphertext",
			record: func(*testing.T) secretRecord {
				record := cloneSecretRecord(base)
				record.ciphertext[0] ^= 0xff
				return record
			},
			provider: func(*testing.T) Provider { return provider },
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			selectedProvider := test.provider(t)
			store, err := newStore(&fakeSecretRecordLoader{record: test.record(t)}, selectedProvider, provider.KeyID())
			if err != nil {
				t.Fatalf("construct secret store: %v", err)
			}
			called := false
			err = store.Use(context.Background(), scope, "secret/identity-key", func([]byte) error {
				called = true
				return nil
			})
			if err != ErrUnavailable || called {
				t.Fatalf("cryptographic mismatch error=%v called=%t", err, called)
			}
			if strings.Contains(err.Error(), "never disclose") {
				t.Fatalf("error exposed plaintext: %v", err)
			}
		})
	}
}

func TestStoreUseRejectsInvalidRequestsAndRecords(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	scope := testSecretScope(t)
	provider := testEnvironmentMasterKey(t, 0x61)
	base := testSecretRecord(t, provider, scope, "attestation-key", 1, []byte("attestation credential"), now)

	validStore := func(record secretRecord) *Store {
		store, err := newStore(&fakeSecretRecordLoader{record: record}, provider, provider.KeyID())
		if err != nil {
			t.Fatalf("construct secret store: %v", err)
		}
		return store
	}
	validConsumer := func([]byte) error { return nil }

	requestTests := []struct {
		name      string
		ctx       context.Context
		scope     Scope
		reference string
		consumer  func([]byte) error
	}{
		{name: "nil context", scope: scope, reference: "secret/attestation-key", consumer: validConsumer},
		{name: "wrong organization ID type", ctx: context.Background(), scope: Scope{OrganizationID: scope.ApplicationID, ApplicationID: scope.ApplicationID, EnvironmentID: scope.EnvironmentID}, reference: "secret/attestation-key", consumer: validConsumer},
		{name: "wrong application ID type", ctx: context.Background(), scope: Scope{OrganizationID: scope.OrganizationID, ApplicationID: scope.EnvironmentID, EnvironmentID: scope.EnvironmentID}, reference: "secret/attestation-key", consumer: validConsumer},
		{name: "wrong environment ID type", ctx: context.Background(), scope: Scope{OrganizationID: scope.OrganizationID, ApplicationID: scope.ApplicationID, EnvironmentID: scope.OrganizationID}, reference: "secret/attestation-key", consumer: validConsumer},
		{name: "untyped reference", ctx: context.Background(), scope: scope, reference: "attestation-key", consumer: validConsumer},
		{name: "noncanonical reference", ctx: context.Background(), scope: scope, reference: "secret/Attestation-Key", consumer: validConsumer},
		{name: "nested reference", ctx: context.Background(), scope: scope, reference: "secret/attestation/key", consumer: validConsumer},
		{name: "nil consumer", ctx: context.Background(), scope: scope, reference: "secret/attestation-key"},
	}
	for _, test := range requestTests {
		t.Run(test.name, func(t *testing.T) {
			if err := validStore(base).Use(test.ctx, test.scope, test.reference, test.consumer); err != ErrInvalid {
				t.Fatalf("invalid request error = %v", err)
			}
		})
	}

	rotatedAt := now.Add(-time.Minute)
	destroyedAt := now.Add(-time.Minute)
	recordTests := []struct {
		name string
		edit func(*secretRecord)
		want error
	}{
		{name: "wrong secret ID type", edit: func(record *secretRecord) { record.id = mustSecretID(t, id.Application) }, want: ErrInvalid},
		{name: "wrong organization", edit: func(record *secretRecord) { record.organizationID = mustSecretID(t, id.Organization) }, want: ErrInvalid},
		{name: "wrong application", edit: func(record *secretRecord) { record.applicationID = mustSecretID(t, id.Application) }, want: ErrInvalid},
		{name: "wrong environment", edit: func(record *secretRecord) { record.environmentID = mustSecretID(t, id.Environment) }, want: ErrInvalid},
		{name: "wrong name", edit: func(record *secretRecord) { record.name = "other" }, want: ErrInvalid},
		{name: "zero version", edit: func(record *secretRecord) { record.version = 0 }, want: ErrInvalid},
		{name: "unsupported format", edit: func(record *secretRecord) { record.formatVersion = 2 }, want: ErrInvalid},
		{name: "wrong algorithm", edit: func(record *secretRecord) { record.storedAlgorithm = "AES-256-GCM" }, want: ErrInvalid},
		{name: "malformed key ID", edit: func(record *secretRecord) { record.masterKeyID = "key\nidentifier" }, want: ErrInvalid},
		{name: "short nonce", edit: func(record *secretRecord) { record.nonce = record.nonce[:11] }, want: ErrInvalid},
		{name: "short ciphertext", edit: func(record *secretRecord) { record.ciphertext = record.ciphertext[:16] }, want: ErrInvalid},
		{name: "zero creation time", edit: func(record *secretRecord) { record.createdAt = time.Time{} }, want: ErrInvalid},
		{name: "rotated version", edit: func(record *secretRecord) { record.rotatedAt = &rotatedAt }, want: ErrUnavailable},
		{name: "destroyed version", edit: func(record *secretRecord) { record.destroyedAt = &destroyedAt }, want: ErrUnavailable},
		{name: "disabled organization", edit: func(record *secretRecord) { record.organizationStatus = "disabled" }, want: ErrUnavailable},
		{name: "disabled application", edit: func(record *secretRecord) { record.applicationStatus = "disabled" }, want: ErrUnavailable},
		{name: "disabled environment", edit: func(record *secretRecord) { record.environmentStatus = "disabled" }, want: ErrUnavailable},
	}
	for _, test := range recordTests {
		t.Run(test.name, func(t *testing.T) {
			record := cloneSecretRecord(base)
			test.edit(&record)
			called := false
			err := validStore(record).Use(context.Background(), scope, "secret/attestation-key", func([]byte) error {
				called = true
				return nil
			})
			if err != test.want || called {
				t.Fatalf("invalid record error=%v want=%v called=%t", err, test.want, called)
			}
		})
	}
}

func TestStoreErrorsAndFormattingAreRedacted(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	scope := testSecretScope(t)
	provider := testEnvironmentMasterKey(t, 0x71)
	record := testSecretRecord(t, provider, scope, "provider-key", 1, []byte("plaintext-for-redaction-test"), now)

	for _, loaderError := range []error{pgx.ErrNoRows, errors.New("database error containing plaintext-for-redaction-test")} {
		store, err := newStore(&fakeSecretRecordLoader{err: loaderError}, provider, provider.KeyID())
		if err != nil {
			t.Fatalf("construct secret store: %v", err)
		}
		if err := store.Use(context.Background(), scope, "secret/provider-key", func([]byte) error { return nil }); err != ErrUnavailable {
			t.Fatalf("loader error was not collapsed: %v", err)
		}
	}

	store, err := newStore(&fakeSecretRecordLoader{record: record}, provider, provider.KeyID())
	if err != nil {
		t.Fatalf("construct secret store: %v", err)
	}
	err = store.Use(context.Background(), scope, "secret/provider-key", func([]byte) error {
		return errors.New("callback failed with plaintext-for-redaction-test")
	})
	if err != ErrInvalid || strings.Contains(err.Error(), "plaintext-for-redaction-test") {
		t.Fatalf("callback error was not redacted: %v", err)
	}

	for _, format := range []string{"%#v", "%+v", "%v", "%s", "%q", "%x"} {
		for label, value := range map[string]any{
			"store pointer":    store,
			"store value":      *store,
			"provider pointer": provider,
			"provider value":   *provider,
			"record":           record,
		} {
			formatted := fmt.Sprintf(format, value)
			if formatted != "[REDACTED]" {
				t.Fatalf("%s format %q = %q", label, format, formatted)
			}
		}
	}
	for label, formatted := range map[string]string{
		"store pointer":    fmt.Sprintf("%p", store),
		"store value":      fmt.Sprintf("%p", *store),
		"provider pointer": fmt.Sprintf("%p", provider),
		"provider value":   fmt.Sprintf("%p", *provider),
		"record":           fmt.Sprintf("%p", record),
	} {
		for _, sensitive := range []string{"plaintext-for-redaction-test", provider.KeyID(), record.id, base64.StdEncoding.EncodeToString(record.ciphertext)} {
			if strings.Contains(formatted, sensitive) {
				t.Fatalf("%%p %s formatting exposed secret metadata: %q", label, formatted)
			}
		}
	}
}

func TestStoreClearsPlaintextReturnedWithDecryptError(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	scope := testSecretScope(t)
	provider := testEnvironmentMasterKey(t, 0x72)
	record := testSecretRecord(t, provider, scope, "provider-key", 1, []byte("encrypted fixture"), now)
	leaked := []byte("provider returned plaintext with error")
	broken := &plaintextOnErrorProvider{keyID: provider.KeyID(), plaintext: leaked}
	store, err := newStore(&fakeSecretRecordLoader{record: record}, broken, broken.KeyID())
	if err != nil {
		t.Fatalf("construct secret store: %v", err)
	}
	if err := store.Use(context.Background(), scope, "secret/provider-key", func([]byte) error { return nil }); err != ErrUnavailable {
		t.Fatalf("broken provider error = %v", err)
	}
	if !allZero(leaked) {
		t.Fatalf("plaintext returned alongside decrypt error was not cleared: %x", leaked)
	}
}

type fakeSecretRecordLoader struct {
	record secretRecord
	err    error
	scope  Scope
	name   string
}

func (loader *fakeSecretRecordLoader) load(_ context.Context, scope Scope, name string) (secretRecord, error) {
	loader.scope = scope
	loader.name = name
	return loader.record, loader.err
}

type providerKeyIDOverride struct {
	Provider
	keyID string
}

func (provider providerKeyIDOverride) KeyID() string { return provider.keyID }

type plaintextOnErrorProvider struct {
	keyID     string
	plaintext []byte
}

func (provider *plaintextOnErrorProvider) Encrypt([]byte, AssociatedData) (Envelope, error) {
	return Envelope{}, errors.New("not implemented in test provider")
}

func (provider *plaintextOnErrorProvider) Decrypt(Envelope, AssociatedData) ([]byte, error) {
	return provider.plaintext, errors.New("decrypt failed after allocating plaintext")
}

func (provider *plaintextOnErrorProvider) KeyID() string { return provider.keyID }

func testSecretScope(t *testing.T) Scope {
	t.Helper()
	return Scope{
		OrganizationID: mustSecretID(t, id.Organization),
		ApplicationID:  mustSecretID(t, id.Application),
		EnvironmentID:  mustSecretID(t, id.Environment),
	}
}

func testEnvironmentMasterKey(t *testing.T, fill byte) *EnvironmentMasterKey {
	t.Helper()
	provider, err := NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32)))
	if err != nil {
		t.Fatalf("construct environment master key: %v", err)
	}
	return provider
}

func testSecretRecord(t *testing.T, provider Provider, scope Scope, name string, version int64, plaintext []byte, now time.Time) secretRecord {
	t.Helper()
	recordID := mustSecretID(t, id.SecretRecord)
	envelope, err := provider.Encrypt(plaintext, AssociatedData{
		OrganizationID: scope.OrganizationID,
		EnvironmentID:  scope.EnvironmentID,
		SecretID:       recordID,
		SecretVersion:  version,
		FormatVersion:  formatVersion,
	})
	if err != nil {
		t.Fatalf("encrypt secret fixture: %v", err)
	}
	return secretRecord{secretRecordMaterial: &secretRecordMaterial{
		id:                 recordID,
		organizationID:     scope.OrganizationID,
		applicationID:      scope.ApplicationID,
		environmentID:      scope.EnvironmentID,
		name:               name,
		version:            version,
		formatVersion:      int16(envelope.FormatVersion),
		storedAlgorithm:    storedEnvelopeAlgorithm,
		masterKeyID:        envelope.KeyID,
		ciphertext:         append([]byte(nil), envelope.Ciphertext...),
		nonce:              append([]byte(nil), envelope.Nonce...),
		createdAt:          now.Add(-time.Minute),
		organizationStatus: "active",
		applicationStatus:  "active",
		environmentStatus:  "active",
	}}
}

func cloneSecretRecord(record secretRecord) secretRecord {
	material := *record.secretRecordMaterial
	record.secretRecordMaterial = &material
	record.ciphertext = append([]byte(nil), record.ciphertext...)
	record.nonce = append([]byte(nil), record.nonce...)
	return record
}

func mustSecretID(t *testing.T, prefix id.Prefix) string {
	t.Helper()
	value, err := id.New(prefix)
	if err != nil {
		t.Fatalf("generate %s ID: %v", prefix, err)
	}
	return value
}

func allZero(value []byte) bool {
	for _, character := range value {
		if character != 0 {
			return false
		}
	}
	return true
}
