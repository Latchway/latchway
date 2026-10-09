package adminapi

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/latchway/latchway/internal/webauthn/webauthntest"
)

type passkeyOptionsDocument struct {
	PublicKey struct {
		Challenge          string              `json:"challenge"`
		RPID               string              `json:"rpId"`
		RP                 struct{ ID string } `json:"rp"`
		User               struct{ ID string } `json:"user"`
		Attestation        string              `json:"attestation"`
		AllowCredentials   []passkeyDescriptor `json:"allowCredentials"`
		ExcludeCredentials []passkeyDescriptor `json:"excludeCredentials"`
	} `json:"public_key"`
}

func (document passkeyOptionsDocument) challenge(t *testing.T) []byte {
	t.Helper()
	challenge, err := b64url.DecodeString(document.PublicKey.Challenge)
	if err != nil || len(challenge) != 32 {
		t.Fatalf("passkey challenge=%q", document.PublicKey.Challenge)
	}
	return challenge
}

func registrationDocument(authenticator *webauthntest.Authenticator, challenge []byte) map[string]any {
	clientData, attestation := authenticator.Register(challenge)
	credentialID := b64url.EncodeToString(authenticator.CredentialID)
	return map[string]any{
		"id": credentialID, "rawId": credentialID, "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64url.EncodeToString(clientData), "attestationObject": b64url.EncodeToString(attestation),
			"transports": []string{"internal"},
		},
	}
}

func assertionDocument(authenticator *webauthntest.Authenticator, challenge []byte) map[string]any {
	clientData, authenticatorData, signature := authenticator.Assert(challenge)
	credentialID := b64url.EncodeToString(authenticator.CredentialID)
	return map[string]any{
		"id": credentialID, "rawId": credentialID, "type": "public-key", "clientExtensionResults": map[string]any{},
		"response": map[string]any{
			"clientDataJSON": b64url.EncodeToString(clientData), "authenticatorData": b64url.EncodeToString(authenticatorData),
			"signature": b64url.EncodeToString(signature), "userHandle": b64url.EncodeToString(authenticator.UserHandle),
		},
	}
}

type addedPasskeyDocument struct {
	Passkey struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Synced bool   `json:"synced"`
	} `json:"passkey"`
	RecoveryCodes []string `json:"recovery_codes"`
}

// registerPasskey adds a software passkey for the session and returns it with the response.
func registerPasskey(t *testing.T, handler http.Handler, session selfServiceSession, password, name string) (*webauthntest.Authenticator, addedPasskeyDocument) {
	t.Helper()
	started := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/passkeys/registration-options", map[string]string{"password": password}, session.cookie, session.csrf, selfServiceOrigin)
	if started.Code != http.StatusOK {
		t.Fatalf("registration options status=%d body=%s", started.Code, started.Body.String())
	}
	var options passkeyOptionsDocument
	decodeResponse(t, started, &options)
	if options.PublicKey.RP.ID != "console.example.test" || options.PublicKey.Attestation != "none" {
		t.Fatalf("registration options=%s", started.Body.String())
	}
	authenticator, err := webauthntest.New("console.example.test", selfServiceOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if authenticator.UserHandle, err = b64url.DecodeString(options.PublicKey.User.ID); err != nil || len(authenticator.UserHandle) != 32 {
		t.Fatalf("user handle=%q", options.PublicKey.User.ID)
	}
	added := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/passkeys", map[string]any{
		"name": name, "credential": registrationDocument(authenticator, options.challenge(t)),
	}, session.cookie, session.csrf, selfServiceOrigin)
	if added.Code != http.StatusCreated {
		t.Fatalf("add passkey status=%d body=%s", added.Code, added.Body.String())
	}
	var document addedPasskeyDocument
	decodeResponse(t, added, &document)
	if document.Passkey.Name != name || !strings.HasPrefix(document.Passkey.ID, "apk_") || !document.Passkey.Synced {
		t.Fatalf("added passkey=%s", added.Body.String())
	}
	return authenticator, document
}

func passkeySignIn(t *testing.T, handler http.Handler, authenticator *webauthntest.Authenticator) (int, selfServiceSession, []byte) {
	t.Helper()
	started := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/passkeys/sign-in-options", map[string]any{}, nil, "", selfServiceOrigin)
	if started.Code != http.StatusOK {
		t.Fatalf("sign-in options status=%d body=%s", started.Code, started.Body.String())
	}
	var options passkeyOptionsDocument
	decodeResponse(t, started, &options)
	if options.PublicKey.RPID != "console.example.test" || len(options.PublicKey.AllowCredentials) != 0 {
		t.Fatalf("sign-in options=%s", started.Body.String())
	}
	response := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/passkeys/sign-in", map[string]any{
		"credential": assertionDocument(authenticator, options.challenge(t)),
	}, nil, "", selfServiceOrigin)
	if response.Code != http.StatusOK {
		return response.Code, selfServiceSession{}, response.Body.Bytes()
	}
	return response.Code, selfServiceSession{cookie: response.Result().Cookies()[0], csrf: response.Header().Get(csrfHeader)}, response.Body.Bytes()
}

func TestPasskeyRelyingPartyNeedsADomainOverHTTPS(t *testing.T) {
	for origin, want := range map[string]string{
		"https://console.example.test":      "console.example.test",
		"https://console.example.test:8443": "console.example.test",
		"http://localhost:5173":             "localhost",
		"http://console.example.test":       "",
		"https://127.0.0.1:8443":            "",
		"https://[::1]:8443":                "",
	} {
		api := &API{publicOrigin: origin}
		rp, ok := api.relyingParty()
		if ok != (want != "") || rp.ID != want || (ok && rp.Origin != origin) {
			t.Fatalf("origin %q relying party=%+v ok=%v", origin, rp, ok)
		}
		if methods := api.signInMethods(); slices.Contains(methods, "passkey") != ok {
			t.Fatalf("origin %q sign-in methods=%v", origin, methods)
		}
	}
}

func TestAdministratorPasskeysPostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	manager := testAdminSecretManager(t, pool)
	api, err := New(pool, selfServiceOrigin, 12*time.Hour, slog.New(slog.NewJSONHandler(io.Discard, nil)), manager, WithFactorSealer(testFactorSealer(t)))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken := strings.Repeat("passkey-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := withUserAgent(router)
	const ownerPassword = "initial owner password"
	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "passkeys",
		"organization_name": "Passkeys", "email": "owner@example.test",
		"display_name": "Owner", "password": ownerPassword,
	}, nil, "", selfServiceOrigin)
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", bootstrap.Code, bootstrap.Body.String())
	}
	var organization struct {
		OrganizationID string `json:"organization_id"`
	}
	decodeResponse(t, bootstrap, &organization)
	owner := selfServiceSession{cookie: bootstrap.Result().Cookies()[0], csrf: bootstrap.Header().Get(csrfHeader)}

	if info := performGET(handler, "/admin/v1/auth/info", nil); !bytes.Contains(info.Body.Bytes(), []byte(`"sign_in_methods":["password","passkey"]`)) {
		t.Fatalf("sign-in info body=%s", info.Body.String())
	}

	// Adding a passkey needs the password, because a passkey can sign in on its own.
	if missing := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/passkeys/registration-options", map[string]string{}, owner.cookie, owner.csrf, selfServiceOrigin); missing.Code != http.StatusBadRequest {
		t.Fatalf("registration without password status=%d", missing.Code)
	}
	if wrong := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/passkeys/registration-options", map[string]string{"password": "not the password"}, owner.cookie, owner.csrf, selfServiceOrigin); wrong.Code != http.StatusForbidden {
		t.Fatalf("registration with wrong password status=%d", wrong.Code)
	}
	laptop, first := registerPasskey(t, handler, owner, ownerPassword, "Laptop")
	if len(first.RecoveryCodes) != 10 {
		t.Fatalf("first passkey recovery codes=%v", first.RecoveryCodes)
	}
	if status := performGET(handler, "/admin/v1/auth/two-factor", owner.cookie); !bytes.Contains(status.Body.Bytes(), []byte(`"enabled":true`)) ||
		!bytes.Contains(status.Body.Bytes(), []byte(`"totp_enabled":false`)) || !bytes.Contains(status.Body.Bytes(), []byte(`"passkeys":1`)) {
		t.Fatalf("status after passkey body=%s", status.Body.String())
	}

	// A registration response works once, and a second passkey keeps the recovery codes.
	started := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/passkeys/registration-options", map[string]string{"password": ownerPassword}, owner.cookie, owner.csrf, selfServiceOrigin)
	var options passkeyOptionsDocument
	decodeResponse(t, started, &options)
	if len(options.PublicKey.ExcludeCredentials) != 1 || options.PublicKey.ExcludeCredentials[0].ID != b64url.EncodeToString(laptop.CredentialID) {
		t.Fatalf("exclude credentials=%+v", options.PublicKey.ExcludeCredentials)
	}
	phone, err := webauthntest.New("console.example.test", selfServiceOrigin)
	if err != nil {
		t.Fatal(err)
	}
	registration := map[string]any{"name": "Phone", "credential": registrationDocument(phone, options.challenge(t))}
	if added := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/passkeys", registration, owner.cookie, owner.csrf, selfServiceOrigin); added.Code != http.StatusCreated ||
		bytes.Contains(added.Body.Bytes(), []byte("recovery_codes")) {
		t.Fatalf("second passkey status=%d body=%s", added.Code, added.Body.String())
	}
	if replayed := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/passkeys", registration, owner.cookie, owner.csrf, selfServiceOrigin); replayed.Code != http.StatusBadRequest {
		t.Fatalf("replayed registration status=%d body=%s", replayed.Code, replayed.Body.String())
	}
	var listed struct {
		Items []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"items"`
	}
	decodeResponse(t, performGET(handler, "/admin/v1/auth/passkeys", owner.cookie), &listed)
	if len(listed.Items) != 2 || listed.Items[0].Name != "Laptop" || listed.Items[1].Name != "Phone" {
		t.Fatalf("passkeys=%+v", listed.Items)
	}

	// A password sign-in now waits for a second factor, which a passkey can give.
	challenge := startSecondFactorLogin(t, handler, "owner@example.test", ownerPassword)
	if !slices.Equal(challenge.Methods, []string{"passkey", "recovery_code"}) {
		t.Fatalf("second-factor methods=%v", challenge.Methods)
	}
	prompt := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login/two-factor/passkey-options", map[string]string{"challenge": challenge.Challenge}, nil, "", selfServiceOrigin)
	var secondFactor passkeyOptionsDocument
	decodeResponse(t, prompt, &secondFactor)
	if prompt.Code != http.StatusOK || len(secondFactor.PublicKey.AllowCredentials) != 2 {
		t.Fatalf("second-factor options status=%d body=%s", prompt.Code, prompt.Body.String())
	}
	assertion := assertionDocument(phone, secondFactor.challenge(t))
	finished := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login/two-factor", map[string]any{"challenge": challenge.Challenge, "passkey": assertion}, nil, "", selfServiceOrigin)
	if finished.Code != http.StatusOK {
		t.Fatalf("passkey second factor status=%d body=%s", finished.Code, finished.Body.String())
	}
	other := startSecondFactorLogin(t, handler, "owner@example.test", ownerPassword)
	if reused := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login/two-factor", map[string]any{"challenge": other.Challenge, "passkey": assertion}, nil, "", selfServiceOrigin); reused.Code != http.StatusUnauthorized {
		t.Fatalf("passkey prompt reused for another sign-in status=%d body=%s", reused.Code, reused.Body.String())
	}

	// A passkey alone signs in, once per prompt, and only from the console's origin.
	code, passkeySession, body := passkeySignIn(t, handler, laptop)
	if code != http.StatusOK || !bytes.Contains(body, []byte(`"two_factor_enrollment_required":false`)) {
		t.Fatalf("passkey sign-in status=%d body=%s", code, body)
	}
	if session := performGET(handler, "/admin/v1/auth/session", passkeySession.cookie); session.Code != http.StatusOK {
		t.Fatalf("passkey session status=%d", session.Code)
	}
	laptop.Counter -= 2
	if code, _, _ := passkeySignIn(t, handler, laptop); code != http.StatusUnauthorized {
		t.Fatalf("counter that went backwards status=%d", code)
	}
	laptop.Counter += 5
	impostor := *laptop
	impostor.Origin = "https://phish.example.test"
	if code, _, _ := passkeySignIn(t, handler, &impostor); code != http.StatusUnauthorized {
		t.Fatalf("passkey from another origin status=%d", code)
	}
	stranger, err := webauthntest.New("console.example.test", selfServiceOrigin)
	if err != nil {
		t.Fatal(err)
	}
	stranger.UserHandle = laptop.UserHandle
	if code, _, _ := passkeySignIn(t, handler, stranger); code != http.StatusUnauthorized {
		t.Fatalf("unregistered passkey status=%d", code)
	}
	if code, _, body := passkeySignIn(t, handler, laptop); code != http.StatusOK {
		t.Fatalf("passkey sign-in after counter recovery status=%d body=%s", code, body)
	}

	// Removing needs the password; the last second factor stays while the organization requires one.
	if wrong := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/passkeys/"+listed.Items[1].ID+"/remove", map[string]string{"password": "not the password"}, owner.cookie, owner.csrf, selfServiceOrigin); wrong.Code != http.StatusForbidden {
		t.Fatalf("remove with wrong password status=%d", wrong.Code)
	}
	if removed := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/passkeys/"+listed.Items[1].ID+"/remove", map[string]string{"password": ownerPassword}, owner.cookie, owner.csrf, selfServiceOrigin); removed.Code != http.StatusNoContent {
		t.Fatalf("remove passkey status=%d body=%s", removed.Code, removed.Body.String())
	}
	if required := performJSON(t, handler, http.MethodPut, "/admin/v1/organizations/"+organization.OrganizationID+"/two-factor-requirement",
		map[string]bool{"required": true}, owner.cookie, owner.csrf, selfServiceOrigin); required.Code != http.StatusOK {
		t.Fatalf("require two-factor status=%d", required.Code)
	}
	if refused := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/passkeys/"+listed.Items[0].ID+"/remove", map[string]string{"password": ownerPassword}, owner.cookie, owner.csrf, selfServiceOrigin); refused.Code != http.StatusConflict {
		t.Fatalf("remove last factor while required status=%d body=%s", refused.Code, refused.Body.String())
	}

	// A member can meet the requirement with a passkey, and an owner reset removes it.
	created := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators", map[string]string{
		"email": "operator@example.test", "display_name": "Operator", "password": "initial operator password", "role": "operator",
	}, owner.cookie, owner.csrf, selfServiceOrigin)
	if created.Code != http.StatusCreated {
		t.Fatalf("create operator status=%d body=%s", created.Code, created.Body.String())
	}
	var operatorRecord struct {
		ID string `json:"id"`
	}
	decodeResponse(t, created, &operatorRecord)
	operator, _ := selfServiceLogin(t, handler, "operator@example.test", "initial operator password", "")
	if changed := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/password", map[string]string{
		"current_password": "initial operator password", "new_password": "operator picked password",
	}, operator.cookie, operator.csrf, selfServiceOrigin); changed.Code != http.StatusOK {
		t.Fatalf("operator password change status=%d body=%s", changed.Code, changed.Body.String())
	}
	operatorKey, _ := registerPasskey(t, handler, operator, "operator picked password", "Security key")
	if allowed := performGET(handler, "/admin/v1/applications?organization_id="+organization.OrganizationID, operator.cookie); allowed.Code != http.StatusOK {
		t.Fatalf("read after passkey enrollment status=%d body=%s", allowed.Code, allowed.Body.String())
	}
	reset := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators/"+operatorRecord.ID+"/reset-two-factor", nil, owner.cookie, owner.csrf, selfServiceOrigin)
	if reset.Code != http.StatusOK || !bytes.Contains(reset.Body.Bytes(), []byte(`"two_factor_enabled":false`)) {
		t.Fatalf("reset status=%d body=%s", reset.Code, reset.Body.String())
	}
	expectEndedSession(t, handler, operator, "session_revoked", "reset your two-factor sign-in")
	if code, _, _ := passkeySignIn(t, handler, operatorKey); code != http.StatusUnauthorized {
		t.Fatalf("passkey sign-in after owner reset status=%d", code)
	}
}
