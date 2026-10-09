package adminapi

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP test vectors use HMAC-SHA-1.
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	secretstore "github.com/latchway/latchway/internal/secrets"
)

// totpCodeAt computes the authenticator code an app would show at instant.
func totpCodeAt(t *testing.T, secret string, instant time.Time) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(instant.Unix()/30))
	mac := hmac.New(sha1.New, raw)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(sum[offset:offset+4])&0x7fffffff)%1_000_000)
}

type twoFactorEnrollment struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

type recoveryCodeList struct {
	RecoveryCodes []string `json:"recovery_codes"`
}

type secondFactorChallenge struct {
	Status    string   `json:"status"`
	Challenge string   `json:"challenge"`
	Methods   []string `json:"methods"`
}

// enrollTOTP sets up an authenticator and returns its key, recovery codes and
// the instant whose time step the confirmation spent.
func testFactorSealer(t *testing.T) factorSealer {
	t.Helper()
	key, err := secretstore.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xc7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func enrollTOTP(t *testing.T, handler http.Handler, session selfServiceSession) (string, []string, time.Time) {
	t.Helper()
	started := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/two-factor/totp", nil, session.cookie, session.csrf, selfServiceOrigin)
	if started.Code != http.StatusOK {
		t.Fatalf("start enrollment status=%d body=%s", started.Code, started.Body.String())
	}
	var enrollment twoFactorEnrollment
	decodeResponse(t, started, &enrollment)
	parsed, err := url.Parse(enrollment.URI)
	if err != nil || parsed.Scheme != "otpauth" || parsed.Query().Get("secret") != enrollment.Secret || !strings.Contains(enrollment.URI, "Latchway%20%28console.example.test%29") {
		t.Fatalf("enrollment uri=%q", enrollment.URI)
	}
	if wrong := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/two-factor/totp/confirm", map[string]string{"code": "000000"}, session.cookie, session.csrf, selfServiceOrigin); wrong.Code != http.StatusBadRequest {
		t.Fatalf("wrong confirmation status=%d body=%s", wrong.Code, wrong.Body.String())
	}
	confirmedAt := time.Now()
	confirmed := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/two-factor/totp/confirm", map[string]string{
		"code": totpCodeAt(t, enrollment.Secret, confirmedAt),
	}, session.cookie, session.csrf, selfServiceOrigin)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm status=%d body=%s", confirmed.Code, confirmed.Body.String())
	}
	var codes recoveryCodeList
	decodeResponse(t, confirmed, &codes)
	if len(codes.RecoveryCodes) != 10 {
		t.Fatalf("recovery codes=%v", codes.RecoveryCodes)
	}
	return enrollment.Secret, codes.RecoveryCodes, confirmedAt
}

func startSecondFactorLogin(t *testing.T, handler http.Handler, email, password string) secondFactorChallenge {
	t.Helper()
	response := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login", map[string]string{"email": email, "password": password}, nil, "", selfServiceOrigin)
	if response.Code != http.StatusAccepted || len(response.Result().Cookies()) != 0 {
		t.Fatalf("password step status=%d cookies=%d body=%s", response.Code, len(response.Result().Cookies()), response.Body.String())
	}
	var challenge secondFactorChallenge
	decodeResponse(t, response, &challenge)
	if challenge.Status != "two_factor_required" || !strings.HasPrefix(challenge.Challenge, "lwsic_") {
		t.Fatalf("challenge=%+v", challenge)
	}
	return challenge
}

func finishSecondFactor(t *testing.T, handler http.Handler, challenge string, body map[string]string) (int, selfServiceSession, []byte) {
	t.Helper()
	body["challenge"] = challenge
	response := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login/two-factor", body, nil, "", selfServiceOrigin)
	if response.Code != http.StatusOK {
		return response.Code, selfServiceSession{}, response.Body.Bytes()
	}
	return response.Code, selfServiceSession{cookie: response.Result().Cookies()[0], csrf: response.Header().Get(csrfHeader)}, response.Body.Bytes()
}

func TestAdministratorTwoFactorPostgreSQL(t *testing.T) {
	databaseURL := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	pool := isolatedAdminAPIPool(t, ctx, databaseURL)
	manager := testAdminSecretManager(t, pool)
	api, err := New(pool, selfServiceOrigin, 12*time.Hour, slog.New(slog.NewJSONHandler(io.Discard, nil)), manager, WithFactorSealer(testFactorSealer(t)))
	if err != nil {
		t.Fatal(err)
	}
	bootstrapToken := strings.Repeat("two-factor-bootstrap-", 2)
	if err := api.InitializeBootstrap(ctx, bootstrapToken); err != nil {
		t.Fatal(err)
	}
	router := chi.NewRouter()
	router.Mount("/admin/v1", api.Handler())
	handler := withUserAgent(router)
	bootstrap := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]string{
		"bootstrap_token": bootstrapToken, "organization_slug": "two-factor",
		"organization_name": "Two Factor", "email": "owner@example.test",
		"display_name": "Owner", "password": "initial owner password",
	}, nil, "", selfServiceOrigin)
	if bootstrap.Code != http.StatusCreated {
		t.Fatalf("bootstrap status=%d body=%s", bootstrap.Code, bootstrap.Body.String())
	}
	var organization struct {
		OrganizationID string `json:"organization_id"`
	}
	decodeResponse(t, bootstrap, &organization)
	owner := selfServiceSession{cookie: bootstrap.Result().Cookies()[0], csrf: bootstrap.Header().Get(csrfHeader)}

	if status := performGET(handler, "/admin/v1/auth/two-factor", owner.cookie); !bytes.Contains(status.Body.Bytes(), []byte(`"totp_enabled":false`)) {
		t.Fatalf("status before enrollment body=%s", status.Body.String())
	}
	secret, recoveryCodes, confirmedAt := enrollTOTP(t, handler, owner)
	if again := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/two-factor/totp", nil, owner.cookie, owner.csrf, selfServiceOrigin); again.Code != http.StatusConflict {
		t.Fatalf("second enrollment status=%d", again.Code)
	}
	if status := performGET(handler, "/admin/v1/auth/two-factor", owner.cookie); !bytes.Contains(status.Body.Bytes(), []byte(`"totp_enabled":true`)) ||
		!bytes.Contains(status.Body.Bytes(), []byte(`"recovery_codes_remaining":10`)) {
		t.Fatalf("status after enrollment body=%s", status.Body.String())
	}

	// A correct password now only starts a sign-in; the confirmation's code can't be replayed.
	challenge := startSecondFactorLogin(t, handler, "owner@example.test", "initial owner password")
	if code, _, body := finishSecondFactor(t, handler, challenge.Challenge, map[string]string{"code": totpCodeAt(t, secret, confirmedAt)}); code != http.StatusUnauthorized {
		t.Fatalf("replayed code status=%d body=%s", code, body)
	}
	code, signedIn, body := finishSecondFactor(t, handler, challenge.Challenge, map[string]string{"code": totpCodeAt(t, secret, confirmedAt.Add(30*time.Second))})
	if code != http.StatusOK || !bytes.Contains(body, []byte(`"two_factor_enrollment_required":false`)) {
		t.Fatalf("second factor status=%d body=%s", code, body)
	}
	if session := performGET(handler, "/admin/v1/auth/session", signedIn.cookie); session.Code != http.StatusOK {
		t.Fatalf("two-factor session status=%d", session.Code)
	}
	if code, _, _ := finishSecondFactor(t, handler, challenge.Challenge, map[string]string{"code": totpCodeAt(t, secret, confirmedAt.Add(30*time.Second))}); code != http.StatusUnauthorized {
		t.Fatalf("reused challenge status=%d", code)
	}

	// A recovery code works once.
	challenge = startSecondFactorLogin(t, handler, "owner@example.test", "initial owner password")
	if code, _, body := finishSecondFactor(t, handler, challenge.Challenge, map[string]string{"recovery_code": strings.ToUpper(recoveryCodes[0])}); code != http.StatusOK {
		t.Fatalf("recovery code status=%d body=%s", code, body)
	}
	challenge = startSecondFactorLogin(t, handler, "owner@example.test", "initial owner password")
	if code, _, _ := finishSecondFactor(t, handler, challenge.Challenge, map[string]string{"recovery_code": recoveryCodes[0]}); code != http.StatusUnauthorized {
		t.Fatalf("spent recovery code status=%d", code)
	}
	if both := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/login/two-factor", map[string]string{
		"challenge": challenge.Challenge, "code": "123456", "recovery_code": recoveryCodes[1],
	}, nil, "", selfServiceOrigin); both.Code != http.StatusBadRequest {
		t.Fatalf("code and recovery code together status=%d", both.Code)
	}

	// The organization can require a second factor; a member without one may only set it up.
	required := performJSON(t, handler, http.MethodPut, "/admin/v1/organizations/"+organization.OrganizationID+"/two-factor-requirement",
		map[string]bool{"required": true}, owner.cookie, owner.csrf, selfServiceOrigin)
	if required.Code != http.StatusOK {
		t.Fatalf("require two-factor status=%d body=%s", required.Code, required.Body.String())
	}
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
	if session := performGET(handler, "/admin/v1/auth/session", operator.cookie); !bytes.Contains(session.Body.Bytes(), []byte(`"two_factor_enrollment_required":true`)) {
		t.Fatalf("operator session body=%s", session.Body.String())
	}
	if blocked := performGET(handler, "/admin/v1/applications?organization_id="+organization.OrganizationID, operator.cookie); blocked.Code != http.StatusForbidden ||
		!bytes.Contains(blocked.Body.Bytes(), []byte("requires two-factor sign-in")) {
		t.Fatalf("enrollment-restricted read status=%d body=%s", blocked.Code, blocked.Body.String())
	}
	operatorSecret, _, operatorConfirmedAt := enrollTOTP(t, handler, operator)
	if allowed := performGET(handler, "/admin/v1/applications?organization_id="+organization.OrganizationID, operator.cookie); allowed.Code != http.StatusOK {
		t.Fatalf("read after enrollment status=%d body=%s", allowed.Code, allowed.Body.String())
	}
	if refused := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/two-factor/disable", map[string]string{
		"password": "operator picked password", "code": totpCodeAt(t, operatorSecret, operatorConfirmedAt.Add(30*time.Second)),
	}, operator.cookie, operator.csrf, selfServiceOrigin); refused.Code != http.StatusConflict {
		t.Fatalf("disable while required status=%d body=%s", refused.Code, refused.Body.String())
	}
	members := performGET(handler, "/admin/v1/administrators", owner.cookie)
	if !bytes.Contains(members.Body.Bytes(), []byte(`"two_factor_enabled":true`)) {
		t.Fatalf("members body=%s", members.Body.String())
	}

	// An owner can reset a member's second factor; the member's sessions end and say why.
	reset := performJSON(t, handler, http.MethodPost, "/admin/v1/administrators/"+operatorRecord.ID+"/reset-two-factor", nil, owner.cookie, owner.csrf, selfServiceOrigin)
	if reset.Code != http.StatusOK || !bytes.Contains(reset.Body.Bytes(), []byte(`"two_factor_enabled":false`)) {
		t.Fatalf("reset two-factor status=%d body=%s", reset.Code, reset.Body.String())
	}
	expectEndedSession(t, handler, operator, "session_revoked", "reset your two-factor sign-in")

	// With the requirement off, a member can turn it off with password and a fresh code.
	if off := performJSON(t, handler, http.MethodPut, "/admin/v1/organizations/"+organization.OrganizationID+"/two-factor-requirement",
		map[string]bool{"required": false}, owner.cookie, owner.csrf, selfServiceOrigin); off.Code != http.StatusOK {
		t.Fatalf("drop requirement status=%d", off.Code)
	}
	if disabled := performJSON(t, handler, http.MethodPost, "/admin/v1/auth/two-factor/disable", map[string]string{
		"password": "initial owner password", "code": totpCodeAt(t, secret, confirmedAt.Add(-30*time.Second)),
	}, owner.cookie, owner.csrf, selfServiceOrigin); disabled.Code != http.StatusForbidden {
		t.Fatalf("disable with an already-used step status=%d body=%s", disabled.Code, disabled.Body.String())
	}

	// Wrong codes end a challenge after five tries, and the per-account limiter stops guessing across challenges.
	challenge = startSecondFactorLogin(t, handler, "owner@example.test", "initial owner password")
	for attempt := range 5 {
		if code, _, body := finishSecondFactor(t, handler, challenge.Challenge, map[string]string{"code": fmt.Sprintf("00000%d", attempt)}); code != http.StatusUnauthorized && code != http.StatusTooManyRequests {
			t.Fatalf("wrong code %d status=%d body=%s", attempt, code, body)
		}
	}
	if code, _, body := finishSecondFactor(t, handler, challenge.Challenge, map[string]string{"recovery_code": recoveryCodes[2]}); code == http.StatusOK {
		t.Fatalf("a challenge signed in after five wrong codes: %s", body)
	}
}
