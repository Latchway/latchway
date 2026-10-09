package secrets

import (
	"bytes"
	"encoding/base64"
	"testing"
)

func TestAdministratorFactorSealingIsBoundToTheAdministrator(t *testing.T) {
	t.Parallel()
	key, err := NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("totp-secret-material")
	sealed, err := key.SealAdministratorFactor(secret, "adm_one")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed.Ciphertext, secret) {
		t.Fatal("sealed factor contains plaintext")
	}
	opened, err := key.OpenAdministratorFactor(sealed, "adm_one")
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("open = %q, %v", opened, err)
	}
	if _, err := key.OpenAdministratorFactor(sealed, "adm_two"); err == nil {
		t.Fatal("a factor sealed for one administrator opened for another")
	}
	// A provider-secret envelope can't stand in for a factor: the derived key differs.
	providerEnvelope, err := key.Encrypt(secret, AssociatedData{OrganizationID: "org", EnvironmentID: "env", SecretID: "sec", SecretVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.OpenAdministratorFactor(providerEnvelope, "adm_one"); err == nil {
		t.Fatal("a provider secret opened as an administrator factor")
	}
	other, err := NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.OpenAdministratorFactor(sealed, "adm_one"); err == nil {
		t.Fatal("a factor opened under a different master key")
	}
}

func TestOrganizationSSOSecretSealingIsBoundToTheOrganizationAndDomain(t *testing.T) {
	t.Parallel()
	key, err := NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("oidc-client-secret")
	sealed, err := key.SealOrganizationSSOSecret(secret, "org_one")
	if err != nil {
		t.Fatal(err)
	}
	opened, err := key.OpenOrganizationSSOSecret(sealed, "org_one")
	if err != nil || !bytes.Equal(opened, secret) {
		t.Fatalf("open = %q, %v", opened, err)
	}
	if _, err := key.OpenOrganizationSSOSecret(sealed, "org_two"); err == nil {
		t.Fatal("a client secret sealed for one organization opened for another")
	}
	// The same binding string under the factor domain must not open it.
	if _, err := key.OpenAdministratorFactor(sealed, "org_one"); err == nil {
		t.Fatal("a client secret opened as an administrator factor")
	}
	factor, err := key.SealAdministratorFactor(secret, "org_one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := key.OpenOrganizationSSOSecret(factor, "org_one"); err == nil {
		t.Fatal("an administrator factor opened as a client secret")
	}
}
