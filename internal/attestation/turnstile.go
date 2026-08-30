package attestation

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

const (
	turnstileProvider       = "turnstile"
	turnstileSiteverifyURL  = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	turnstileEvidenceDomain = "latchway/turnstile-evidence/v1"

	maxTurnstileTokenBytes     = 2048
	maxTurnstileSecretBytes    = 4096
	maxTurnstileResponseBytes  = 32 << 10
	defaultTurnstileTimeout    = 5 * time.Second
	maximumTurnstileTimeout    = 30 * time.Second
	defaultTurnstileMaximumAge = 5 * time.Minute
	maximumTurnstileMaximumAge = 10 * time.Minute
	defaultTurnstileClockSkew  = 30 * time.Second
	maximumTurnstileClockSkew  = 5 * time.Minute
	defaultTurnstileResult     = 5 * time.Minute
	maximumTurnstileResult     = time.Hour
	defaultTurnstileAttempts   = 2
	maximumTurnstileAttempts   = 3
	defaultTurnstileRetryDelay = 50 * time.Millisecond
)

var (
	ErrTurnstileService      = errors.New("turnstile service is unavailable")
	turnstileHostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`)
	turnstileActionPattern   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)
	turnstileUUIDPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// TurnstileSecretCapability supplies plaintext only for the lifetime of a
// synchronous callback. Implementations must clear their temporary buffer as
// soon as Use returns and must never include provider material in errors.
type TurnstileSecretCapability interface {
	Use(context.Context, func([]byte) error) error
}

type TurnstileConfig struct {
	ApplicationID    string
	EnvironmentID    string
	AllowedHostnames []string
	ExpectedAction   string
	Secret           TurnstileSecretCapability
	Transport        http.RoundTripper
	Timeout          time.Duration
	Now              func() time.Time
	MaximumAge       time.Duration
	ClockSkew        time.Duration
	ClockSkewSet     bool
	ResultLifetime   time.Duration
	MaximumAttempts  int
	RetryDelay       time.Duration
}

type TurnstileVerifier struct {
	applicationID   string
	environmentID   string
	hostnames       map[string]struct{}
	expectedAction  string
	secret          TurnstileSecretCapability
	client          *http.Client
	now             func() time.Time
	timeout         time.Duration
	maximumAge      time.Duration
	clockSkew       time.Duration
	resultLifetime  time.Duration
	maximumAttempts int
	retryDelay      time.Duration
}

func NewTurnstileVerifier(config TurnstileConfig) (*TurnstileVerifier, error) {
	if !applicationPattern.MatchString(config.ApplicationID) ||
		!environmentPattern.MatchString(config.EnvironmentID) ||
		len(config.AllowedHostnames) == 0 || len(config.AllowedHostnames) > 32 ||
		!turnstileActionPattern.MatchString(config.ExpectedAction) ||
		nilPlayIntegrityDependency(config.Secret) ||
		(config.Transport != nil && nilPlayIntegrityDependency(config.Transport)) {
		return nil, ErrConfiguration
	}
	hostnames := make(map[string]struct{}, len(config.AllowedHostnames))
	for _, hostname := range config.AllowedHostnames {
		if !validTurnstileHostname(hostname) {
			return nil, ErrConfiguration
		}
		if _, duplicate := hostnames[hostname]; duplicate {
			return nil, ErrConfiguration
		}
		hostnames[hostname] = struct{}{}
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Timeout == 0 {
		config.Timeout = defaultTurnstileTimeout
	}
	if config.Timeout < time.Second || config.Timeout > maximumTurnstileTimeout {
		return nil, ErrConfiguration
	}
	if config.MaximumAge == 0 {
		config.MaximumAge = defaultTurnstileMaximumAge
	}
	if config.MaximumAge < 30*time.Second || config.MaximumAge > maximumTurnstileMaximumAge {
		return nil, ErrConfiguration
	}
	if !config.ClockSkewSet && config.ClockSkew == 0 {
		config.ClockSkew = defaultTurnstileClockSkew
	}
	if config.ClockSkew < 0 || config.ClockSkew > maximumTurnstileClockSkew {
		return nil, ErrConfiguration
	}
	if config.ResultLifetime == 0 {
		config.ResultLifetime = defaultTurnstileResult
	}
	if config.ResultLifetime < time.Minute || config.ResultLifetime > maximumTurnstileResult {
		return nil, ErrConfiguration
	}
	if config.MaximumAttempts == 0 {
		config.MaximumAttempts = defaultTurnstileAttempts
	}
	if config.MaximumAttempts < 1 || config.MaximumAttempts > maximumTurnstileAttempts {
		return nil, ErrConfiguration
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = defaultTurnstileRetryDelay
	}
	if config.RetryDelay < 0 || config.RetryDelay > time.Second {
		return nil, ErrConfiguration
	}
	transport := config.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return &TurnstileVerifier{
		applicationID: config.ApplicationID, environmentID: config.EnvironmentID,
		hostnames: hostnames, expectedAction: config.ExpectedAction, secret: config.Secret,
		client: client, now: config.Now, timeout: config.Timeout,
		maximumAge: config.MaximumAge, clockSkew: config.ClockSkew,
		resultLifetime: config.ResultLifetime, maximumAttempts: config.MaximumAttempts,
		retryDelay: config.RetryDelay,
	}, nil
}

func (*TurnstileVerifier) ID() string { return turnstileProvider }

func (verifier *TurnstileVerifier) Verify(
	ctx context.Context,
	evidence Evidence,
	binding Binding,
) (Result, error) {
	if verifier == nil || evidence.provider != turnstileProvider {
		return Result{}, ErrUnsupported
	}
	if ctx == nil {
		return Result{}, invalid("turnstile context")
	}
	if verifier.client == nil || verifier.now == nil || verifier.maximumAttempts < 1 ||
		nilPlayIntegrityDependency(verifier.secret) {
		return Result{}, ErrConfiguration
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := binding.Validate(); err != nil {
		return Result{}, err
	}
	if binding.ApplicationID != verifier.applicationID || binding.Environment != verifier.environmentID ||
		binding.Platform != "web" {
		return Result{}, invalid("turnstile binding scope")
	}
	if len(evidence.payload) != 1 {
		return Result{}, invalid("turnstile evidence shape")
	}
	token, ok := evidence.payload["token"].(string)
	if !ok || !validTurnstileMaterial(token, maxTurnstileTokenBytes) {
		return Result{}, invalid("turnstile token")
	}
	bindingHash, err := binding.Hash()
	if err != nil {
		return Result{}, err
	}
	// The browser adapter must render the widget with cData equal to this
	// unpadded base64url binding digest. Siteverify returns that authenticated
	// value, giving the web risk signal an exact challenge/identity/DPoP scope.
	expectedCData := base64.RawURLEncoding.EncodeToString(bindingHash[:])
	idempotencyKey, err := newTurnstileUUID()
	if err != nil {
		return Result{}, ErrTurnstileService
	}

	var verdict turnstileVerdict
	for attempt := 0; attempt < verifier.maximumAttempts; attempt++ {
		verdict, err = verifier.verifyAttempt(ctx, token, idempotencyKey)
		if err == nil {
			break
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Result{}, ctxErr
		}
		if !errors.Is(err, errTurnstileTransient) {
			if errors.Is(err, ErrInvalid) {
				return Result{}, err
			}
			return Result{}, ErrTurnstileService
		}
		if attempt+1 == verifier.maximumAttempts {
			return Result{}, ErrTurnstileService
		}
		if err := waitTurnstileRetry(ctx, verifier.retryDelay); err != nil {
			return Result{}, err
		}
	}
	if err != nil {
		return Result{}, ErrTurnstileService
	}
	now := verifier.now().UTC()
	if now.IsZero() || now.Year() < 1 || now.Year() > 9998 {
		return Result{}, ErrConfiguration
	}
	if verdict.challengeAt.Before(now.Add(-verifier.maximumAge)) ||
		verdict.challengeAt.After(now.Add(verifier.clockSkew)) ||
		time.Unix(binding.IssuedAt, 0).After(verdict.challengeAt.Add(verifier.clockSkew)) {
		return Result{}, invalid("turnstile challenge freshness")
	}
	if _, allowed := verifier.hostnames[verdict.hostname]; !allowed {
		return Result{}, invalid("turnstile hostname")
	}
	if verdict.action != verifier.expectedAction {
		return Result{}, invalid("turnstile action")
	}
	if len(verdict.cdata) != len(expectedCData) ||
		!constantTimeStringEqual(verdict.cdata, expectedCData) {
		return Result{}, invalid("turnstile binding")
	}
	signals := map[string]any{
		"risk_valid":        true,
		"binding_verified":  true,
		"verified_hostname": verdict.hostname,
		"verified_action":   verdict.action,
	}
	return newResult(
		turnstileProvider, "web_risk_verified", now, now.Add(verifier.resultLifetime),
		signals, turnstileEvidenceHash(token), bindingHash,
	)
}

var errTurnstileTransient = errors.New("transient turnstile failure")

type turnstileVerdict struct {
	challengeAt time.Time
	hostname    string
	action      string
	cdata       string
}

func (verifier *TurnstileVerifier) verifyAttempt(
	ctx context.Context,
	token string,
	idempotencyKey string,
) (turnstileVerdict, error) {
	var verdict turnstileVerdict
	var operationErr error
	uses := 0
	secretErr := verifier.secret.Use(ctx, func(secret []byte) error {
		uses++
		if uses != 1 || !validTurnstileSecret(secret) {
			operationErr = ErrTurnstileService
			return nil
		}
		verdict, operationErr = verifier.dispatchSiteverify(ctx, secret, token, idempotencyKey)
		return nil
	})
	if secretErr != nil || uses != 1 {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return turnstileVerdict{}, ctxErr
		}
		return turnstileVerdict{}, ErrTurnstileService
	}
	return verdict, operationErr
}

func (verifier *TurnstileVerifier) dispatchSiteverify(
	ctx context.Context,
	secret []byte,
	token string,
	idempotencyKey string,
) (turnstileVerdict, error) {
	body := turnstileSiteverifyBody(secret, token, idempotencyKey)
	defer clear(body)
	requestContext, cancel := context.WithTimeout(ctx, verifier.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(
		requestContext, http.MethodPost, turnstileSiteverifyURL, bytes.NewReader(body),
	)
	if err != nil {
		return turnstileVerdict{}, ErrTurnstileService
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "latchway/turnstile-v1")
	response, err := verifier.client.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return turnstileVerdict{}, contextErr
		}
		if requestContext.Err() != nil {
			return turnstileVerdict{}, errTurnstileTransient
		}
		return turnstileVerdict{}, errTurnstileTransient
	}
	if response == nil {
		return turnstileVerdict{}, errTurnstileTransient
	}
	if response.StatusCode >= 500 {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		return turnstileVerdict{}, errTurnstileTransient
	}
	if response.StatusCode != http.StatusOK {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		return turnstileVerdict{}, ErrTurnstileService
	}
	if response.Body == nil {
		return turnstileVerdict{}, ErrTurnstileService
	}
	encoded, readErr := io.ReadAll(io.LimitReader(response.Body, maxTurnstileResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return turnstileVerdict{}, contextErr
		}
		if requestContext.Err() != nil {
			return turnstileVerdict{}, errTurnstileTransient
		}
		return turnstileVerdict{}, ErrTurnstileService
	}
	if closeErr != nil {
		return turnstileVerdict{}, ErrTurnstileService
	}
	if len(encoded) > maxTurnstileResponseBytes {
		return turnstileVerdict{}, ErrTurnstileService
	}
	defer clear(encoded)
	mediaType, _, contentTypeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if contentTypeErr != nil || mediaType != "application/json" {
		return turnstileVerdict{}, ErrTurnstileService
	}
	verdict, transient, parseErr := parseTurnstileResponse(encoded)
	if parseErr != nil {
		return turnstileVerdict{}, parseErr
	}
	if transient {
		return turnstileVerdict{}, errTurnstileTransient
	}
	if err := ctx.Err(); err != nil {
		return turnstileVerdict{}, err
	}
	if requestContext.Err() != nil {
		return turnstileVerdict{}, errTurnstileTransient
	}
	return verdict, nil
}

func turnstileSiteverifyBody(secret []byte, token string, idempotencyKey string) []byte {
	body := make([]byte, 0, len(secret)+len(token)+len(idempotencyKey)+40)
	body = append(body, "secret="...)
	body = appendTurnstileFormBytes(body, secret)
	body = append(body, "&response="...)
	body = appendTurnstileFormString(body, token)
	body = append(body, "&idempotency_key="...)
	return appendTurnstileFormString(body, idempotencyKey)
}

func appendTurnstileFormBytes(destination []byte, value []byte) []byte {
	for _, character := range value {
		destination = appendTurnstileFormByte(destination, character)
	}
	return destination
}

func appendTurnstileFormString(destination []byte, value string) []byte {
	for index := 0; index < len(value); index++ {
		destination = appendTurnstileFormByte(destination, value[index])
	}
	return destination
}

func appendTurnstileFormByte(destination []byte, character byte) []byte {
	if (character >= 'a' && character <= 'z') ||
		(character >= 'A' && character <= 'Z') ||
		(character >= '0' && character <= '9') ||
		character == '-' || character == '.' || character == '_' || character == '~' {
		return append(destination, character)
	}
	if character == ' ' {
		return append(destination, '+')
	}
	const hexadecimal = "0123456789ABCDEF"
	return append(destination, '%', hexadecimal[character>>4], hexadecimal[character&0x0f])
}

func parseTurnstileResponse(encoded []byte) (turnstileVerdict, bool, error) {
	if len(encoded) == 0 || len(encoded) > maxTurnstileResponseBytes {
		return turnstileVerdict{}, false, ErrTurnstileService
	}
	value, err := jsonsafe.Decode(encoded)
	if err != nil {
		return turnstileVerdict{}, false, ErrTurnstileService
	}
	document, ok := value.(map[string]any)
	if !ok || len(document) == 0 || len(document) > 32 {
		return turnstileVerdict{}, false, ErrTurnstileService
	}
	success, ok := document["success"].(bool)
	if !ok {
		return turnstileVerdict{}, false, ErrTurnstileService
	}
	errorCodes, ok := optionalTurnstileErrorCodes(document["error-codes"])
	if !ok {
		return turnstileVerdict{}, false, ErrTurnstileService
	}
	if !success {
		if len(errorCodes) == 1 && errorCodes[0] == "internal-error" {
			return turnstileVerdict{}, true, nil
		}
		return turnstileVerdict{}, false, invalid("turnstile verdict")
	}
	if len(errorCodes) != 0 {
		return turnstileVerdict{}, false, invalid("turnstile verdict")
	}
	challengeText, challengeOK := stringMember(document, "challenge_ts", 20, 64)
	hostname, hostnameOK := stringMember(document, "hostname", 1, 253)
	action, actionOK := stringMember(document, "action", 1, 32)
	cdata, cdataOK := stringMember(document, "cdata", 43, 255)
	if !challengeOK || !hostnameOK || !validTurnstileHostname(hostname) ||
		!actionOK || !turnstileActionPattern.MatchString(action) || !cdataOK {
		return turnstileVerdict{}, false, invalid("turnstile verdict fields")
	}
	challengeAt, err := time.Parse(time.RFC3339Nano, challengeText)
	if err != nil || challengeAt.Location() != time.UTC {
		return turnstileVerdict{}, false, invalid("turnstile challenge timestamp")
	}
	return turnstileVerdict{
		challengeAt: challengeAt.UTC(), hostname: hostname, action: action, cdata: cdata,
	}, false, nil
}

func optionalTurnstileErrorCodes(value any) ([]string, bool) {
	if value == nil {
		return nil, true
	}
	items, ok := value.([]any)
	if !ok || len(items) > 16 {
		return nil, false
	}
	result := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		code, ok := item.(string)
		if !ok || code == "" || len(code) > 64 || strings.TrimSpace(code) != code ||
			strings.ContainsAny(code, "\r\n\x00") {
			return nil, false
		}
		if _, duplicate := seen[code]; duplicate {
			return nil, false
		}
		seen[code] = struct{}{}
		result = append(result, code)
	}
	return result, true
}

func validTurnstileHostname(hostname string) bool {
	if len(hostname) > 253 || hostname != strings.ToLower(hostname) ||
		!turnstileHostnamePattern.MatchString(hostname) || strings.Contains(hostname, "..") {
		return false
	}
	for _, label := range strings.Split(hostname, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func validTurnstileMaterial(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for _, character := range value {
		if character <= ' ' || character > '~' {
			return false
		}
	}
	return true
}

func validTurnstileSecret(secret []byte) bool {
	if len(secret) == 0 || len(secret) > maxTurnstileSecretBytes {
		return false
	}
	for _, character := range secret {
		if character <= ' ' || character > '~' {
			return false
		}
	}
	return true
}

func newTurnstileUUID() (string, error) {
	var value [16]byte
	if _, err := io.ReadFull(rand.Reader, value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	result := fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16],
	)
	if !turnstileUUIDPattern.MatchString(result) {
		return "", ErrTurnstileService
	}
	return result, nil
}

func waitTurnstileRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func constantTimeStringEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func turnstileEvidenceHash(token string) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write([]byte(turnstileEvidenceDomain))
	digest.Write([]byte{0})
	digest.Write([]byte(strconv.Itoa(len(token))))
	digest.Write([]byte{0})
	digest.Write([]byte(token))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func (TurnstileVerifier) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "TurnstileVerifier{[REDACTED]}")
}

func (TurnstileVerifier) LogValue() slog.Value {
	return slog.StringValue("TurnstileVerifier{[REDACTED]}")
}

var _ Verifier = (*TurnstileVerifier)(nil)
