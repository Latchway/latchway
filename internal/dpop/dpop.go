// Package dpop validates RFC 9449 proof JWTs using an explicitly constrained
// ES256 profile.
package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/latchway/latchway/internal/jsonsafe"
)

const (
	maxProofBytes = 16 << 10
	maxJTIBytes   = 128
	defaultMaxAge = 5 * time.Minute
	defaultSkew   = time.Minute
)

// Error identifies a safe, stable DPoP validation failure.
type Error struct {
	Code string
}

func (e *Error) Error() string { return e.Code }

// IsCode reports whether err is a DPoP error with code.
func IsCode(err error, code string) bool {
	var validationErr *Error
	return errors.As(err, &validationErr) && validationErr.Code == code
}

// PublicJWK is the allowed P-256 public-key representation.
type PublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// Thumbprint returns the RFC 7638 SHA-256 JWK thumbprint.
func (j PublicJWK) Thumbprint() (string, error) {
	if _, err := j.PublicKey(); err != nil {
		return "", err
	}
	canonical := []byte(`{"crv":"` + j.Crv + `","kty":"` + j.Kty + `","x":"` + j.X + `","y":"` + j.Y + `"}`)
	digest := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

// PublicKey validates and converts the JWK.
func (j PublicJWK) PublicKey() (*ecdsa.PublicKey, error) {
	if j.Kty != "EC" || j.Crv != "P-256" {
		return nil, validationError("dpop_invalid")
	}
	xBytes, err := decodeCoordinate(j.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := decodeCoordinate(j.Y)
	if err != nil {
		return nil, err
	}
	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)
	curve := elliptic.P256()
	if x.Sign() == 0 || y.Sign() == 0 || !curve.IsOnCurve(x, y) {
		return nil, validationError("dpop_invalid")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// Options supplies the request-bound values required by RFC 9449.
type Options struct {
	Method            string
	URI               *url.URL
	AccessToken       string
	ExpectedJKT       string
	ExpectedNonce     string
	Now               time.Time
	MaxAge            time.Duration
	ClockSkew         time.Duration
	ClockSkewSet      bool
	RequireAccessHash bool
}

// Result contains validated, non-secret proof attributes.
type Result struct {
	JKT      string
	JTI      string
	IssuedAt time.Time
	Nonce    string
	JWK      PublicJWK
}

// Validate verifies a compact DPoP proof and all supplied request bindings.
func Validate(proof string, opts Options) (Result, error) {
	if len(proof) == 0 || len(proof) > maxProofBytes {
		return Result{}, validationError("dpop_invalid")
	}
	if opts.Method == "" || opts.URI == nil {
		return Result{}, errors.New("dpop validator requires method and URI")
	}

	segments := strings.Split(proof, ".")
	if len(segments) != 3 || segments[0] == "" || segments[1] == "" || segments[2] == "" {
		return Result{}, validationError("dpop_invalid")
	}
	headerBytes, err := decodeSegment(segments[0])
	if err != nil {
		return Result{}, validationError("dpop_invalid")
	}
	payloadBytes, err := decodeSegment(segments[1])
	if err != nil {
		return Result{}, validationError("dpop_invalid")
	}
	signature, err := decodeSegment(segments[2])
	if err != nil || len(signature) != 64 {
		return Result{}, validationError("dpop_invalid")
	}

	headerValue, err := jsonsafe.Decode(headerBytes)
	if err != nil {
		return Result{}, validationError("dpop_invalid")
	}
	header, ok := headerValue.(map[string]any)
	if !ok {
		return Result{}, validationError("dpop_invalid")
	}
	if stringValue(header["typ"]) != "dpop+jwt" || stringValue(header["alg"]) != "ES256" {
		return Result{}, validationError("dpop_invalid")
	}
	for _, forbidden := range []string{"jku", "x5u", "x5c", "crit", "b64", "zip"} {
		if _, present := header[forbidden]; present {
			return Result{}, validationError("dpop_invalid")
		}
	}
	jwkMap, ok := header["jwk"].(map[string]any)
	if !ok {
		return Result{}, validationError("dpop_invalid")
	}
	jwk, err := parsePublicJWK(jwkMap)
	if err != nil {
		return Result{}, err
	}
	publicKey, err := jwk.PublicKey()
	if err != nil {
		return Result{}, err
	}
	digest := sha256.Sum256([]byte(segments[0] + "." + segments[1]))
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	if r.Sign() <= 0 || s.Sign() <= 0 || !ecdsa.Verify(publicKey, digest[:], r, s) {
		return Result{}, validationError("dpop_invalid")
	}

	payloadValue, err := jsonsafe.Decode(payloadBytes)
	if err != nil {
		return Result{}, validationError("dpop_invalid")
	}
	claims, ok := payloadValue.(map[string]any)
	if !ok {
		return Result{}, validationError("dpop_invalid")
	}
	jti := stringValue(claims["jti"])
	method := stringValue(claims["htm"])
	htu := stringValue(claims["htu"])
	issuedAt, err := numericDate(claims["iat"])
	if !validJTI(jti) || method == "" || htu == "" || err != nil {
		return Result{}, validationError("dpop_invalid")
	}
	if subtle.ConstantTimeCompare([]byte(method), []byte(opts.Method)) != 1 {
		return Result{}, validationError("dpop_invalid")
	}
	expectedHTU, err := NormalizeHTU(opts.URI)
	if err != nil {
		return Result{}, errors.New("invalid expected DPoP URI")
	}
	proofURI, err := url.Parse(htu)
	if err != nil || proofURI.RawQuery != "" || proofURI.Fragment != "" {
		return Result{}, validationError("dpop_invalid")
	}
	actualHTU, err := NormalizeHTU(proofURI)
	if err != nil || subtle.ConstantTimeCompare([]byte(actualHTU), []byte(expectedHTU)) != 1 {
		return Result{}, validationError("dpop_invalid")
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	maxAge := opts.MaxAge
	if maxAge <= 0 {
		maxAge = defaultMaxAge
	}
	skew := opts.ClockSkew
	if !opts.ClockSkewSet && skew == 0 {
		skew = defaultSkew
	}
	if skew < 0 || skew > 5*time.Minute {
		return Result{}, errors.New("invalid DPoP clock-skew option")
	}
	issuedTime := time.Unix(issuedAt, 0)
	if issuedTime.After(now.Add(skew)) || issuedTime.Before(now.Add(-maxAge-skew)) {
		return Result{}, validationError("dpop_invalid")
	}

	nonce := stringValue(claims["nonce"])
	if len(nonce) > 512 || strings.ContainsAny(nonce, "\r\n\x00") {
		return Result{}, validationError("dpop_invalid")
	}
	if opts.ExpectedNonce != "" && subtle.ConstantTimeCompare([]byte(nonce), []byte(opts.ExpectedNonce)) != 1 {
		return Result{}, validationError("dpop_nonce_required")
	}
	ath := stringValue(claims["ath"])
	requireATH := opts.RequireAccessHash || opts.AccessToken != ""
	if requireATH {
		if opts.AccessToken == "" || ath == "" {
			return Result{}, validationError("dpop_invalid")
		}
		expectedATH := AccessTokenHash(opts.AccessToken)
		if subtle.ConstantTimeCompare([]byte(ath), []byte(expectedATH)) != 1 {
			return Result{}, validationError("dpop_invalid")
		}
	} else if ath != "" {
		return Result{}, validationError("dpop_invalid")
	}

	jkt, err := jwk.Thumbprint()
	if err != nil {
		return Result{}, err
	}
	if opts.ExpectedJKT != "" && subtle.ConstantTimeCompare([]byte(jkt), []byte(opts.ExpectedJKT)) != 1 {
		return Result{}, validationError("dpop_invalid")
	}

	return Result{JKT: jkt, JTI: jti, IssuedAt: issuedTime, Nonce: nonce, JWK: jwk}, nil
}

// AccessTokenHash returns the RFC 9449 ath claim value.
func AccessTokenHash(accessToken string) string {
	digest := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

// NormalizeHTU applies conservative RFC 3986 syntax- and scheme-based
// normalization and always removes query and fragment components.
func NormalizeHTU(uri *url.URL) (string, error) {
	if uri == nil || uri.User != nil || uri.Scheme == "" || uri.Host == "" {
		return "", errors.New("absolute URI without userinfo required")
	}
	scheme := strings.ToLower(uri.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("only HTTP and HTTPS URIs are supported")
	}
	hostname := strings.ToLower(uri.Hostname())
	if hostname == "" || !isASCII(hostname) || strings.Contains(hostname, "%") {
		return "", errors.New("ASCII hostname without a zone identifier required")
	}
	port := uri.Port()
	if (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		parsedPort, err := strconv.Atoi(port)
		if err != nil || parsedPort < 1 || parsedPort > 65535 {
			return "", errors.New("invalid URI port")
		}
		host = net.JoinHostPort(hostname, port)
	}

	normalizedPath, err := normalizePath(uri.EscapedPath())
	if err != nil {
		return "", err
	}
	return scheme + "://" + host + normalizedPath, nil
}

func normalizePath(escaped string) (string, error) {
	if escaped == "" {
		return "/", nil
	}
	var builder strings.Builder
	for index := 0; index < len(escaped); index++ {
		if escaped[index] != '%' {
			builder.WriteByte(escaped[index])
			continue
		}
		if index+2 >= len(escaped) {
			return "", errors.New("invalid percent encoding")
		}
		value, err := strconv.ParseUint(escaped[index+1:index+3], 16, 8)
		if err != nil {
			return "", errors.New("invalid percent encoding")
		}
		decoded := byte(value)
		if isUnreserved(decoded) {
			builder.WriteByte(decoded)
		} else {
			builder.WriteByte('%')
			builder.WriteString(strings.ToUpper(escaped[index+1 : index+3]))
		}
		index += 2
	}
	cleaned := removeDotSegments(builder.String())
	if cleaned == "" || !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned, nil
}

func removeDotSegments(input string) string {
	var output string
	for input != "" {
		switch {
		case strings.HasPrefix(input, "../"):
			input = input[3:]
		case strings.HasPrefix(input, "./"):
			input = input[2:]
		case strings.HasPrefix(input, "/./"):
			input = "/" + input[3:]
		case input == "/.":
			input = "/"
		case strings.HasPrefix(input, "/../"):
			input = "/" + input[4:]
			output = removeLastPathSegment(output)
		case input == "/..":
			input = "/"
			output = removeLastPathSegment(output)
		case input == "." || input == "..":
			input = ""
		default:
			segmentEnd := 0
			if strings.HasPrefix(input, "/") {
				segmentEnd = strings.Index(input[1:], "/")
				if segmentEnd >= 0 {
					segmentEnd++
				}
			} else {
				segmentEnd = strings.Index(input, "/")
			}
			if segmentEnd < 0 {
				output += input
				input = ""
			} else {
				output += input[:segmentEnd]
				input = input[segmentEnd:]
			}
		}
	}
	return output
}

func removeLastPathSegment(value string) string {
	if index := strings.LastIndex(value, "/"); index >= 0 {
		return value[:index]
	}
	return ""
}

func parsePublicJWK(values map[string]any) (PublicJWK, error) {
	for member := range values {
		switch member {
		case "kty", "crv", "x", "y":
		default:
			if member == "d" || member == "p" || member == "q" || member == "dp" || member == "dq" || member == "qi" || member == "oth" || member == "k" {
				return PublicJWK{}, validationError("dpop_invalid")
			}
			// Embedded proof keys are self-contained. Reject even ignored remote
			// key metadata so it cannot acquire meaning in a future refactor.
			return PublicJWK{}, validationError("dpop_invalid")
		}
	}
	jwk := PublicJWK{
		Kty: stringValue(values["kty"]),
		Crv: stringValue(values["crv"]),
		X:   stringValue(values["x"]),
		Y:   stringValue(values["y"]),
	}
	if _, err := jwk.PublicKey(); err != nil {
		return PublicJWK{}, err
	}
	return jwk, nil
}

func decodeCoordinate(encoded string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		return nil, validationError("dpop_invalid")
	}
	return decoded, nil
}

func decodeSegment(segment string) ([]byte, error) {
	if strings.Contains(segment, "=") {
		return nil, errors.New("JWT segments must use unpadded base64url")
	}
	decoded, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != segment {
		return nil, errors.New("invalid base64url")
	}
	return decoded, nil
}

func numericDate(value any) (int64, error) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, errors.New("numeric date required")
	}
	return number.Int64()
}

func validJTI(value string) bool {
	return len(value) >= 1 && len(value) <= maxJTIBytes &&
		utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) == -1
}

func stringValue(value any) string {
	stringValue, _ := value.(string)
	return stringValue
}

func validationError(code string) error { return &Error{Code: code} }

func isUnreserved(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' || value == '-' || value == '.' || value == '_' || value == '~'
}

func isASCII(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] > 0x7f {
			return false
		}
	}
	return true
}
