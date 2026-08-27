package secrets

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestCheckMasterKeyConsistency(t *testing.T) {
	t.Parallel()

	const keyID = "env_current-key"
	tests := []struct {
		name      string
		inspector masterKeyRecordInspector
		keyID     string
		want      error
	}{
		{name: "no mismatch", inspector: &fakeMasterKeyRecordInspector{}, keyID: keyID},
		{name: "mismatch", inspector: &fakeMasterKeyRecordInspector{mismatch: true}, keyID: keyID, want: ErrMasterKeyMismatch},
		{name: "query failure", inspector: &fakeMasterKeyRecordInspector{err: errors.New("database failure containing env_sensitive-key-id")}, keyID: keyID, want: ErrMasterKeyCheckUnavailable},
		{name: "nil inspector", keyID: keyID, want: ErrMasterKeyCheckUnavailable},
		{name: "malformed key identifier", inspector: &fakeMasterKeyRecordInspector{}, keyID: "env_bad\nidentifier", want: ErrMasterKeyCheckUnavailable},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := checkMasterKeyConsistency(context.Background(), test.inspector, test.keyID)
			if !errors.Is(err, test.want) || (test.want == nil && err != nil) {
				t.Fatalf("check error = %v, want %v", err, test.want)
			}
			if err != nil && strings.Contains(err.Error(), "env_sensitive-key-id") {
				t.Fatalf("check error exposed persisted key metadata: %v", err)
			}
		})
	}
}

func TestCheckMasterKeyConsistencyPassesOnlyIdentifierToInspector(t *testing.T) {
	t.Parallel()

	inspector := &fakeMasterKeyRecordInspector{}
	const keyID = "env_expected-key"
	if err := checkMasterKeyConsistency(context.Background(), inspector, keyID); err != nil {
		t.Fatalf("check master-key consistency: %v", err)
	}
	if inspector.keyID != keyID {
		t.Fatalf("inspector key ID = %q, want %q", inspector.keyID, keyID)
	}
}

type fakeMasterKeyRecordInspector struct {
	mismatch bool
	err      error
	keyID    string
}

func (inspector *fakeMasterKeyRecordInspector) hasMismatchedSecretKey(_ context.Context, keyID string) (bool, error) {
	inspector.keyID = keyID
	return inspector.mismatch, inspector.err
}
