package attestation

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/jsonsafe"
)

const (
	playIntegrityProvider              = "play_integrity"
	playIntegrityEvidenceDomain        = "latchway/play-integrity-evidence/v1"
	playIntegrityDevice                = "device"
	playIntegrityStrongDevice          = "strong"
	defaultPlayIntegrityMaximumAge     = 2 * time.Minute
	maximumPlayIntegrityMaximumAge     = 10 * time.Minute
	defaultPlayIntegrityClockSkew      = 30 * time.Second
	maximumPlayIntegrityClockSkew      = 5 * time.Minute
	defaultPlayIntegrityResultLifetime = 10 * time.Minute
	maximumPlayIntegrityResultLifetime = 24 * time.Hour
	maxPlayIntegrityDecodedBytes       = 64 << 10
	maxPlayIntegrityTokenBytes         = 60 << 10
	maxPlayIntegrityCertificates       = 16
)

var (
	// ErrPlayIntegrityService is deliberately redaction-safe. Decoder and
	// credential implementations must not wrap Google payloads or tokens into it.
	ErrPlayIntegrityService = errors.New("play integrity service is unavailable")

	playIntegrityPackagePattern = regexp.MustCompile(
		`^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$`,
	)
	playIntegrityTokenPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// PlayIntegrityTokenDecoder exchanges an opaque Standard API token for the
// authenticated Google DecodeIntegrityTokenResponse JSON document. The
// implementation is a trusted server dependency; the verifier still treats
// every returned byte as untrusted and parses it with strict size and duplicate
// member checks. CloudProjectNumber identifies the project whose credentials
// and Play Console linkage the decoder uses.
type PlayIntegrityTokenDecoder interface {
	CloudProjectNumber() int64
	DecodeIntegrityToken(context.Context, string, string) ([]byte, error)
}

// PlayIntegrityConfig contains only server-owned expectations. Certificate
// digests use Google's base64url SHA-256 representation; padded and unpadded
// canonical encodings are accepted and compared as bytes. The initial native
// verifier intentionally requires a physical device verdict (device or strong)
// and never promotes virtual/basic-only verdicts to device trust.
type PlayIntegrityConfig struct {
	ApplicationID            string
	EnvironmentID            string
	PackageName              string
	CloudProjectNumber       int64
	CertificateSHA256Digests []string
	MinimumDeviceIntegrity   string
	RequireLicensed          bool
	AllowTestingResponses    bool
	MinimumVersionCode       int64
	MaximumVersionCode       int64
	Decoder                  PlayIntegrityTokenDecoder
	Now                      func() time.Time
	MaximumAge               time.Duration
	ClockSkew                time.Duration
	ClockSkewSet             bool
	ResultLifetime           time.Duration
}

type PlayIntegrityVerifier struct {
	applicationID          string
	environmentID          string
	packageName            string
	cloudProjectNumber     int64
	certificates           map[[sha256.Size]byte]struct{}
	minimumDeviceIntegrity string
	requireLicensed        bool
	allowTestingResponses  bool
	minimumVersionCode     int64
	maximumVersionCode     int64
	decoder                PlayIntegrityTokenDecoder
	now                    func() time.Time
	maximumAge             time.Duration
	clockSkew              time.Duration
	resultLifetime         time.Duration
}

func NewPlayIntegrityVerifier(config PlayIntegrityConfig) (*PlayIntegrityVerifier, error) {
	if !applicationPattern.MatchString(config.ApplicationID) ||
		!environmentPattern.MatchString(config.EnvironmentID) ||
		!validPlayIntegrityPackage(config.PackageName) || config.CloudProjectNumber <= 0 ||
		nilPlayIntegrityDependency(config.Decoder) ||
		config.Decoder.CloudProjectNumber() != config.CloudProjectNumber ||
		(config.MinimumDeviceIntegrity != playIntegrityDevice &&
			config.MinimumDeviceIntegrity != playIntegrityStrongDevice) ||
		config.MinimumVersionCode < 0 || config.MaximumVersionCode < 0 ||
		(config.MaximumVersionCode != 0 &&
			(config.MinimumVersionCode == 0 || config.MaximumVersionCode < config.MinimumVersionCode)) {
		return nil, ErrConfiguration
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaximumAge == 0 {
		config.MaximumAge = defaultPlayIntegrityMaximumAge
	}
	if !config.ClockSkewSet && config.ClockSkew == 0 {
		config.ClockSkew = defaultPlayIntegrityClockSkew
	}
	if config.ResultLifetime == 0 {
		config.ResultLifetime = defaultPlayIntegrityResultLifetime
	}
	if config.MaximumAge < 30*time.Second || config.MaximumAge > maximumPlayIntegrityMaximumAge ||
		config.ClockSkew < 0 || config.ClockSkew > maximumPlayIntegrityClockSkew ||
		config.ResultLifetime < time.Minute || config.ResultLifetime > maximumPlayIntegrityResultLifetime {
		return nil, ErrConfiguration
	}
	if len(config.CertificateSHA256Digests) == 0 ||
		len(config.CertificateSHA256Digests) > maxPlayIntegrityCertificates {
		return nil, ErrConfiguration
	}
	certificates := make(map[[sha256.Size]byte]struct{}, len(config.CertificateSHA256Digests))
	for _, encoded := range config.CertificateSHA256Digests {
		digest, err := decodePlayIntegrityCertificateDigest(encoded)
		if err != nil {
			return nil, ErrConfiguration
		}
		if _, duplicate := certificates[digest]; duplicate {
			return nil, ErrConfiguration
		}
		certificates[digest] = struct{}{}
	}
	return &PlayIntegrityVerifier{
		applicationID: config.ApplicationID, environmentID: config.EnvironmentID,
		packageName: config.PackageName, cloudProjectNumber: config.CloudProjectNumber,
		certificates: certificates, minimumDeviceIntegrity: config.MinimumDeviceIntegrity,
		requireLicensed: config.RequireLicensed, allowTestingResponses: config.AllowTestingResponses,
		minimumVersionCode: config.MinimumVersionCode, maximumVersionCode: config.MaximumVersionCode,
		decoder: config.Decoder, now: config.Now, maximumAge: config.MaximumAge,
		clockSkew: config.ClockSkew, resultLifetime: config.ResultLifetime,
	}, nil
}

func (*PlayIntegrityVerifier) ID() string { return playIntegrityProvider }

func (verifier *PlayIntegrityVerifier) Verify(
	ctx context.Context,
	evidence Evidence,
	binding Binding,
) (Result, error) {
	if verifier == nil || evidence.provider != playIntegrityProvider {
		return Result{}, ErrUnsupported
	}
	if nilPlayIntegrityDependency(verifier.decoder) || verifier.now == nil ||
		verifier.packageName == "" || verifier.cloudProjectNumber <= 0 {
		return Result{}, ErrConfiguration
	}
	if ctx == nil {
		return Result{}, invalid("play integrity context")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	if err := binding.Validate(); err != nil {
		return Result{}, err
	}
	if binding.ApplicationID != verifier.applicationID || binding.Environment != verifier.environmentID ||
		(binding.Platform != "android" && binding.Platform != "react_native_android") {
		return Result{}, invalid("play integrity binding scope")
	}
	if len(evidence.payload) != 1 {
		return Result{}, invalid("play integrity evidence shape")
	}
	token, ok := evidence.payload["integrity_token"].(string)
	if !ok || len(token) < 16 || len(token) > maxPlayIntegrityTokenBytes ||
		!playIntegrityTokenPattern.MatchString(token) {
		return Result{}, invalid("play integrity token")
	}

	decoded, err := verifier.decoder.DecodeIntegrityToken(ctx, verifier.packageName, token)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return Result{}, ctxErr
		}
		if errors.Is(err, ErrPlayIntegrityTokenRejected) {
			return Result{}, invalid("play integrity token rejection")
		}
		return Result{}, ErrPlayIntegrityService
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	payload, err := parsePlayIntegrityDecodeResponse(decoded)
	if err != nil {
		return Result{}, err
	}
	now := verifier.now().UTC()
	if now.IsZero() || now.Year() < 1 || now.Year() > 9998 {
		return Result{}, ErrConfiguration
	}
	bindingHash, err := binding.Hash()
	if err != nil {
		return Result{}, err
	}
	verdict, err := verifier.validatePayload(payload, binding, bindingHash, now)
	if err != nil {
		return Result{}, err
	}

	evidenceHash := playIntegrityEvidenceHash(token)
	trustLevel := "device_verified"
	if verdict.strongDevice {
		trustLevel = "strong_device_verified"
	}
	if verdict.testingResponse {
		trustLevel = "debug"
	}
	signals := map[string]any{
		"app_identity_valid":         true,
		"device_valid":               true,
		"licensed":                   verdict.licensed,
		"verified_app_id":            verifier.packageName,
		"verified_version":           strconv.FormatInt(verdict.versionCode, 10),
		"app_recognition_verdict":    "PLAY_RECOGNIZED",
		"device_recognition_verdict": append([]string(nil), verdict.deviceVerdicts...),
		"app_licensing_verdict":      verdict.licensingVerdict,
		"cloud_project_number":       strconv.FormatInt(verifier.cloudProjectNumber, 10),
		"testing_response":           verdict.testingResponse,
	}
	return newResult(
		playIntegrityProvider, trustLevel, now, now.Add(verifier.resultLifetime),
		signals, evidenceHash, bindingHash,
	)
}

type playIntegrityPayload struct {
	requestPackageName string
	requestHash        string
	timestampMillis    int64
	appVerdict         string
	appPackageName     string
	certificateDigests [][sha256.Size]byte
	versionCode        int64
	deviceVerdicts     []string
	licensingVerdict   string
	testingResponse    bool
}

type validatedPlayIntegrityVerdict struct {
	versionCode      int64
	deviceVerdicts   []string
	licensingVerdict string
	licensed         bool
	strongDevice     bool
	testingResponse  bool
}

func (verifier *PlayIntegrityVerifier) validatePayload(
	payload playIntegrityPayload,
	binding Binding,
	bindingHash [sha256.Size]byte,
	now time.Time,
) (validatedPlayIntegrityVerdict, error) {
	expectedHash := base64.RawURLEncoding.EncodeToString(bindingHash[:])
	if payload.requestPackageName != verifier.packageName || payload.appPackageName != verifier.packageName ||
		len(payload.requestHash) != len(expectedHash) ||
		subtle.ConstantTimeCompare([]byte(payload.requestHash), []byte(expectedHash)) != 1 ||
		payload.appVerdict != "PLAY_RECOGNIZED" {
		return validatedPlayIntegrityVerdict{}, invalid("play integrity request or app binding")
	}
	if payload.timestampMillis < 0 || payload.timestampMillis > 253402300799999 ||
		payload.timestampMillis < now.Add(-verifier.maximumAge).UnixMilli() ||
		payload.timestampMillis > now.Add(verifier.clockSkew).UnixMilli() ||
		binding.IssuedAt > (payload.timestampMillis+verifier.clockSkew.Milliseconds())/1000 {
		return validatedPlayIntegrityVerdict{}, invalid("play integrity request freshness")
	}
	if len(payload.certificateDigests) == 0 || len(payload.certificateDigests) > maxPlayIntegrityCertificates {
		return validatedPlayIntegrityVerdict{}, invalid("play integrity application certificate")
	}
	seenCertificates := make(map[[sha256.Size]byte]struct{}, len(payload.certificateDigests))
	for _, certificate := range payload.certificateDigests {
		if _, duplicate := seenCertificates[certificate]; duplicate {
			return validatedPlayIntegrityVerdict{}, invalid("play integrity application certificate")
		}
		seenCertificates[certificate] = struct{}{}
		if _, allowed := verifier.certificates[certificate]; !allowed {
			return validatedPlayIntegrityVerdict{}, invalid("play integrity application certificate")
		}
	}
	if payload.versionCode <= 0 ||
		(verifier.minimumVersionCode != 0 && payload.versionCode < verifier.minimumVersionCode) ||
		(verifier.maximumVersionCode != 0 && payload.versionCode > verifier.maximumVersionCode) {
		return validatedPlayIntegrityVerdict{}, invalid("play integrity application version")
	}

	deviceRank, strong, err := playIntegrityPhysicalDeviceRank(payload.deviceVerdicts)
	if err != nil {
		return validatedPlayIntegrityVerdict{}, err
	}
	requiredRank := 2
	if verifier.minimumDeviceIntegrity == playIntegrityStrongDevice {
		requiredRank = 3
	}
	if deviceRank < requiredRank {
		return validatedPlayIntegrityVerdict{}, invalid("play integrity device verdict")
	}
	licensed := payload.licensingVerdict == "LICENSED"
	if !slices.Contains([]string{"LICENSED", "UNLICENSED", "UNEVALUATED", "UNKNOWN"}, payload.licensingVerdict) ||
		(verifier.requireLicensed && !licensed) {
		return validatedPlayIntegrityVerdict{}, invalid("play integrity licensing verdict")
	}
	if payload.testingResponse && !verifier.allowTestingResponses {
		return validatedPlayIntegrityVerdict{}, invalid("play integrity testing response")
	}
	return validatedPlayIntegrityVerdict{
		versionCode: payload.versionCode, deviceVerdicts: append([]string(nil), payload.deviceVerdicts...),
		licensingVerdict: payload.licensingVerdict, licensed: licensed,
		strongDevice: strong, testingResponse: payload.testingResponse,
	}, nil
}

func parsePlayIntegrityDecodeResponse(encoded []byte) (playIntegrityPayload, error) {
	if len(encoded) == 0 || len(encoded) > maxPlayIntegrityDecodedBytes {
		return playIntegrityPayload{}, invalid("play integrity decode response size")
	}
	decoded, err := jsonsafe.Decode(encoded)
	if err != nil {
		return playIntegrityPayload{}, invalid("play integrity decode response JSON")
	}
	envelope, ok := decoded.(map[string]any)
	if !ok || len(envelope) != 1 {
		return playIntegrityPayload{}, invalid("play integrity decode response shape")
	}
	tokenPayload, ok := objectMember(envelope, "tokenPayloadExternal")
	if !ok {
		return playIntegrityPayload{}, invalid("play integrity token payload")
	}
	request, ok := objectMember(tokenPayload, "requestDetails")
	if !ok {
		return playIntegrityPayload{}, invalid("play integrity request details")
	}
	app, ok := objectMember(tokenPayload, "appIntegrity")
	if !ok {
		return playIntegrityPayload{}, invalid("play integrity app details")
	}
	device, ok := objectMember(tokenPayload, "deviceIntegrity")
	if !ok {
		return playIntegrityPayload{}, invalid("play integrity device details")
	}
	account, ok := objectMember(tokenPayload, "accountDetails")
	if !ok {
		return playIntegrityPayload{}, invalid("play integrity account details")
	}

	requestPackageName, ok := stringMember(request, "requestPackageName", 1, 255)
	if !ok {
		return playIntegrityPayload{}, invalid("play integrity request package")
	}
	requestHash, ok := stringMember(request, "requestHash", 43, 43)
	if !ok || validateBase64URL(requestHash, sha256.Size, sha256.Size) != nil {
		return playIntegrityPayload{}, invalid("play integrity request hash")
	}
	if nonce, exists := request["nonce"]; exists && nonce != nil && nonce != "" {
		return playIntegrityPayload{}, invalid("play integrity request mode")
	}
	timestampText, ok := stringMember(request, "timestampMillis", 1, 18)
	if !ok {
		return playIntegrityPayload{}, invalid("play integrity request timestamp")
	}
	timestampMillis, err := parseUnsignedDecimal(timestampText, 253402300799999)
	if err != nil {
		return playIntegrityPayload{}, invalid("play integrity request timestamp")
	}

	appVerdict, ok := stringMember(app, "appRecognitionVerdict", 1, 64)
	if !ok {
		return playIntegrityPayload{}, invalid("play integrity app verdict")
	}
	appPackageName, ok := stringMember(app, "packageName", 1, 255)
	if !ok {
		return playIntegrityPayload{}, invalid("play integrity app package")
	}
	versionText, ok := stringMember(app, "versionCode", 1, 19)
	if !ok {
		return playIntegrityPayload{}, invalid("play integrity app version")
	}
	versionCode, err := parseUnsignedDecimal(versionText, int64(^uint64(0)>>1))
	if err != nil {
		return playIntegrityPayload{}, invalid("play integrity app version")
	}
	certificateTexts, ok := stringArrayMember(app, "certificateSha256Digest", maxPlayIntegrityCertificates, 128)
	if !ok || len(certificateTexts) == 0 {
		return playIntegrityPayload{}, invalid("play integrity app certificate")
	}
	certificateDigests := make([][sha256.Size]byte, 0, len(certificateTexts))
	for _, encodedDigest := range certificateTexts {
		digest, decodeErr := decodePlayIntegrityCertificateDigest(encodedDigest)
		if decodeErr != nil {
			return playIntegrityPayload{}, invalid("play integrity app certificate")
		}
		certificateDigests = append(certificateDigests, digest)
	}
	deviceVerdicts, ok := stringArrayMember(device, "deviceRecognitionVerdict", 8, 64)
	if !ok || len(deviceVerdicts) == 0 {
		return playIntegrityPayload{}, invalid("play integrity device verdict")
	}
	licensingVerdict, ok := stringMember(account, "appLicensingVerdict", 1, 64)
	if !ok {
		return playIntegrityPayload{}, invalid("play integrity licensing verdict")
	}
	testingResponse := false
	if testingValue, exists := tokenPayload["testingDetails"]; exists {
		testing, ok := testingValue.(map[string]any)
		if !ok || len(testing) != 1 {
			return playIntegrityPayload{}, invalid("play integrity testing details")
		}
		flag, ok := testing["isTestingResponse"].(bool)
		if !ok {
			return playIntegrityPayload{}, invalid("play integrity testing details")
		}
		testingResponse = flag
	}
	return playIntegrityPayload{
		requestPackageName: requestPackageName, requestHash: requestHash,
		timestampMillis: timestampMillis, appVerdict: appVerdict,
		appPackageName: appPackageName, certificateDigests: certificateDigests,
		versionCode: versionCode, deviceVerdicts: deviceVerdicts,
		licensingVerdict: licensingVerdict, testingResponse: testingResponse,
	}, nil
}

func objectMember(object map[string]any, key string) (map[string]any, bool) {
	value, ok := object[key]
	if !ok {
		return nil, false
	}
	result, ok := value.(map[string]any)
	return result, ok && result != nil
}

func stringMember(object map[string]any, key string, minimum, maximum int) (string, bool) {
	value, ok := object[key].(string)
	return value, ok && len(value) >= minimum && len(value) <= maximum && strings.TrimSpace(value) == value
}

func stringArrayMember(object map[string]any, key string, maximumItems, maximumLength int) ([]string, bool) {
	values, ok := object[key].([]any)
	if !ok || len(values) == 0 || len(values) > maximumItems {
		return nil, false
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok || text == "" || len(text) > maximumLength || strings.TrimSpace(text) != text {
			return nil, false
		}
		result = append(result, text)
	}
	return result, true
}

func parseUnsignedDecimal(value string, maximum int64) (int64, error) {
	if value == "" || len(value) > 1 && value[0] == '0' || strings.ContainsAny(value, "+-. ") {
		return 0, ErrInvalid
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 || parsed > maximum {
		return 0, ErrInvalid
	}
	return parsed, nil
}

func decodePlayIntegrityCertificateDigest(encoded string) ([sha256.Size]byte, error) {
	var result [sha256.Size]byte
	var decoded []byte
	var err error
	if strings.Contains(encoded, "=") {
		decoded, err = base64.URLEncoding.Strict().DecodeString(encoded)
		if err == nil && base64.URLEncoding.EncodeToString(decoded) != encoded {
			err = ErrInvalid
		}
	} else {
		decoded, err = base64.RawURLEncoding.Strict().DecodeString(encoded)
		if err == nil && base64.RawURLEncoding.EncodeToString(decoded) != encoded {
			err = ErrInvalid
		}
	}
	if err != nil || len(decoded) != sha256.Size {
		return result, ErrInvalid
	}
	copy(result[:], decoded)
	if result == ([sha256.Size]byte{}) {
		return [sha256.Size]byte{}, ErrInvalid
	}
	return result, nil
}

func playIntegrityPhysicalDeviceRank(verdicts []string) (int, bool, error) {
	if len(verdicts) == 0 || len(verdicts) > 8 {
		return 0, false, invalid("play integrity device verdict")
	}
	seen := make(map[string]struct{}, len(verdicts))
	rank := 0
	virtual := false
	for _, verdict := range verdicts {
		if _, duplicate := seen[verdict]; duplicate {
			return 0, false, invalid("play integrity device verdict")
		}
		seen[verdict] = struct{}{}
		switch verdict {
		case "MEETS_BASIC_INTEGRITY":
			rank = max(rank, 1)
		case "MEETS_DEVICE_INTEGRITY":
			rank = max(rank, 2)
		case "MEETS_STRONG_INTEGRITY":
			rank = max(rank, 3)
		case "MEETS_VIRTUAL_INTEGRITY":
			virtual = true
		case "UNKNOWN":
			return 0, false, invalid("play integrity device verdict")
		default:
			return 0, false, invalid("play integrity device verdict")
		}
	}
	if virtual && rank != 0 {
		return 0, false, invalid("play integrity device verdict")
	}
	return rank, rank >= 3, nil
}

func nilPlayIntegrityDependency(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validPlayIntegrityPackage(packageName string) bool {
	return len(packageName) <= 255 && playIntegrityPackagePattern.MatchString(packageName)
}

func playIntegrityEvidenceHash(token string) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write([]byte(playIntegrityEvidenceDomain))
	digest.Write([]byte{0})
	digest.Write([]byte(strconv.Itoa(len(token))))
	digest.Write([]byte{0})
	digest.Write([]byte(token))
	var result [sha256.Size]byte
	copy(result[:], digest.Sum(nil))
	return result
}

func (payload playIntegrityPayload) String() string { return "[REDACTED]" }
func (payload playIntegrityPayload) GoString() string {
	return "attestation.playIntegrityPayload{[REDACTED]}"
}

var _ Verifier = (*PlayIntegrityVerifier)(nil)
