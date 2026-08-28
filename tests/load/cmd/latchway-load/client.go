package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/dpop"
)

const maximumResponseBytes = 4 << 20

type protectedClient struct {
	baseURL     *url.URL
	accessToken string
	key         *ecdsa.PrivateKey
	publicJWK   dpop.PublicJWK
	http        *http.Client
}

type privateJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

type requestResult struct {
	Status      int
	Latency     time.Duration
	Body        []byte `json:"-"`
	ProblemCode string
	FirstByteAt time.Time
	Err         error
}

func newProtectedClient(cfg config) (*protectedClient, error) {
	accessToken := strings.TrimSpace(os.Getenv(cfg.Session.AccessTokenEnv))
	if len(accessToken) < 64 || len(accessToken) > 16<<10 || strings.ContainsAny(accessToken, "\r\n\x00") {
		return nil, fmt.Errorf("%s must contain one bounded DPoP access token", cfg.Session.AccessTokenEnv)
	}
	keyPath := strings.TrimSpace(os.Getenv(cfg.Session.PrivateJWKEnv))
	if keyPath == "" {
		return nil, fmt.Errorf("%s must name a private P-256 JWK file", cfg.Session.PrivateJWKEnv)
	}
	key, public, err := loadPrivateJWK(keyPath)
	if err != nil {
		return nil, err
	}
	baseURL, err := url.Parse(cfg.Gateway.BaseURL)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConns = max(1024, cfg.Targets.SSEConcurrency+64)
	transport.MaxIdleConnsPerHost = max(1024, cfg.Targets.SSEConcurrency+64)
	transport.MaxConnsPerHost = 0
	transport.ForceAttemptHTTP2 = true
	return &protectedClient{
		baseURL: baseURL, accessToken: accessToken, key: key, publicJWK: public,
		http: &http.Client{Transport: transport},
	}, nil
}

func loadPrivateJWK(path string) (*ecdsa.PrivateKey, dpop.PublicJWK, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, dpop.PublicJWK{}, fmt.Errorf("stat private JWK: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, dpop.PublicJWK{}, errors.New("private JWK must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, dpop.PublicJWK{}, errors.New("private JWK must not be group- or world-accessible")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, dpop.PublicJWK{}, fmt.Errorf("read private JWK: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var value privateJWK
	if err := decoder.Decode(&value); err != nil {
		return nil, dpop.PublicJWK{}, errors.New("decode private JWK")
	}
	if value.Kty != "EC" || value.Crv != "P-256" {
		return nil, dpop.PublicJWK{}, errors.New("private JWK must use EC P-256")
	}
	x, err := decodeCoordinate(value.X)
	if err != nil {
		return nil, dpop.PublicJWK{}, errors.New("private JWK x coordinate is invalid")
	}
	y, err := decodeCoordinate(value.Y)
	if err != nil {
		return nil, dpop.PublicJWK{}, errors.New("private JWK y coordinate is invalid")
	}
	dBytes, err := base64.RawURLEncoding.Strict().DecodeString(value.D)
	if err != nil || len(dBytes) != 32 || base64.RawURLEncoding.EncodeToString(dBytes) != value.D {
		return nil, dpop.PublicJWK{}, errors.New("private JWK scalar is invalid")
	}
	d := new(big.Int).SetBytes(dBytes)
	curve := elliptic.P256()
	if d.Sign() <= 0 || d.Cmp(curve.Params().N) >= 0 || !curve.IsOnCurve(x, y) {
		return nil, dpop.PublicJWK{}, errors.New("private JWK point is invalid")
	}
	wantX, wantY := curve.ScalarBaseMult(dBytes)
	if wantX.Cmp(x) != 0 || wantY.Cmp(y) != 0 {
		return nil, dpop.PublicJWK{}, errors.New("private JWK public point does not match its scalar")
	}
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: curve, X: x, Y: y}, D: d},
		dpop.PublicJWK{Kty: value.Kty, Crv: value.Crv, X: value.X, Y: value.Y}, nil
}

func decodeCoordinate(value string) (*big.Int, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("invalid coordinate")
	}
	return new(big.Int).SetBytes(decoded), nil
}

func (client *protectedClient) target(path string) *url.URL {
	target := *client.baseURL
	target.Path = strings.TrimRight(target.Path, "/") + path
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	return &target
}

func (client *protectedClient) request(ctx context.Context, specification requestConfig) (*http.Request, error) {
	target := client.target(specification.Path)
	method := strings.ToUpper(specification.Method)
	proof, err := client.proof(method, target)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if method != http.MethodGet && method != http.MethodHead {
		body = bytes.NewReader(specification.Body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, err
	}
	for key, value := range specification.Headers {
		request.Header.Set(key, value)
	}
	request.Header.Set("Authorization", "DPoP "+client.accessToken)
	request.Header.Set("DPoP", proof)
	return request, nil
}

func (client *protectedClient) proof(method string, target *url.URL) (string, error) {
	header, err := json.Marshal(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256", "jwk": client.publicJWK,
	})
	if err != nil {
		return "", err
	}
	jti := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, jti); err != nil {
		return "", errors.New("generate DPoP jti")
	}
	htu, err := dpop.NormalizeHTU(target)
	if err != nil {
		return "", errors.New("normalize DPoP target")
	}
	claims, err := json.Marshal(map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"htm": method,
		"htu": htu,
		"iat": time.Now().UTC().Unix(),
		"ath": dpop.AccessTokenHash(client.accessToken),
	})
	if err != nil {
		return "", err
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	claimSegment := base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(headerSegment + "." + claimSegment))
	r, s, err := ecdsa.Sign(rand.Reader, client.key, digest[:])
	if err != nil {
		return "", errors.New("sign DPoP proof")
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return headerSegment + "." + claimSegment + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (client *protectedClient) execute(ctx context.Context, specification requestConfig) requestResult {
	started := time.Now()
	request, err := client.request(ctx, specification)
	if err != nil {
		return requestResult{Latency: time.Since(started), Err: err}
	}
	response, err := client.http.Do(request)
	if err != nil {
		return requestResult{Latency: time.Since(started), Err: err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	latency := time.Since(started)
	if err != nil {
		return requestResult{Status: response.StatusCode, Latency: latency, Err: err}
	}
	if len(body) > maximumResponseBytes {
		return requestResult{Status: response.StatusCode, Latency: latency, Err: errors.New("response exceeds 4 MiB evidence bound")}
	}
	return requestResult{
		Status: response.StatusCode, Latency: latency, Body: body,
		ProblemCode: stableProblemCode(response.StatusCode, body),
	}
}

func executeBaseline(ctx context.Context, httpClient *http.Client, cfg config) requestResult {
	started := time.Now()
	request, err := http.NewRequestWithContext(ctx, strings.ToUpper(cfg.NonStream.Method), cfg.Baseline.URL, bytes.NewReader(cfg.Baseline.Body))
	if err != nil {
		return requestResult{Err: err}
	}
	for key, value := range cfg.Baseline.Headers {
		request.Header.Set(key, value)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return requestResult{Latency: time.Since(started), Err: err}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err == nil && len(body) > maximumResponseBytes {
		err = errors.New("direct upstream response exceeds 4 MiB evidence bound")
	}
	return requestResult{
		Status: response.StatusCode, Latency: time.Since(started), Body: body,
		ProblemCode: stableProblemCode(response.StatusCode, body), Err: err,
	}
}

func stableProblemCode(status int, body []byte) string {
	if status < http.StatusBadRequest || len(body) == 0 {
		return ""
	}
	var problem struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(body, &problem); err != nil || !validEvidenceCode(problem.Code) {
		return ""
	}
	return problem.Code
}

func validateExpectedJSON(result requestResult, expectedStatus int) error {
	if result.Err != nil {
		return result.Err
	}
	if result.Status != expectedStatus {
		return fmt.Errorf("status %d, want %d", result.Status, expectedStatus)
	}
	if expectedStatus >= 200 && expectedStatus < 300 && !json.Valid(result.Body) {
		return errors.New("successful non-stream response is not one JSON value")
	}
	return nil
}

type quotaSnapshot struct {
	Feature    string       `json:"feature"`
	ObservedAt time.Time    `json:"observed_at"`
	Limits     []quotaLimit `json:"limits"`
}

type quotaLimit struct {
	Metric    string     `json:"metric"`
	Maximum   *int64     `json:"maximum"`
	Used      *int64     `json:"used"`
	Reserved  *int64     `json:"reserved"`
	Remaining *int64     `json:"remaining"`
	ResetsAt  *time.Time `json:"resets_at"`
	Hard      bool       `json:"hard"`
}

func (client *protectedClient) quotaSnapshot(ctx context.Context, path string, headerSource requestConfig) (quotaSnapshot, error) {
	specification := requestConfig{
		Method: "GET", Path: path, Headers: map[string]string{}, Body: json.RawMessage("null"), ExpectedStatus: http.StatusOK,
	}
	for key, value := range headerSource.Headers {
		if strings.EqualFold(key, "Content-Type") || strings.EqualFold(key, "Content-Length") {
			continue
		}
		specification.Headers[key] = value
	}
	result := client.execute(ctx, specification)
	if result.Err != nil {
		return quotaSnapshot{}, result.Err
	}
	if result.Status != http.StatusOK {
		return quotaSnapshot{}, fmt.Errorf("quota snapshot status %d", result.Status)
	}
	var snapshot quotaSnapshot
	decoder := json.NewDecoder(bytes.NewReader(result.Body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&snapshot); err != nil {
		return quotaSnapshot{}, errors.New("quota snapshot response is invalid")
	}
	return snapshot, nil
}

func requestID(index int) string {
	random := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, random); err != nil {
		return "load-" + strconv.Itoa(index) + "-entropy-failed"
	}
	return "load-" + strconv.Itoa(index) + "-" + base64.RawURLEncoding.EncodeToString(random)
}
