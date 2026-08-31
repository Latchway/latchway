package main

import (
	"bufio"
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
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/dpop"
)

const maximumResponseBytes = 4 << 20

type requestConfig struct {
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Headers        map[string]string `json:"headers"`
	Body           json.RawMessage   `json:"body"`
	ExpectedStatus int               `json:"expected_status"`
}

type loadConfig struct {
	SchemaVersion int             `json:"schema_version"`
	Environment   json.RawMessage `json:"environment"`
	Gateway       struct {
		BaseURL             string `json:"base_url"`
		ReadyPath           string `json:"ready_path"`
		PID                 int    `json:"pid"`
		ProcessNameContains string `json:"process_name_contains"`
	} `json:"gateway"`
	Session struct {
		AccessTokenEnvironment string `json:"access_token_env"`
		PrivateJWKEnvironment  string `json:"private_jwk_file_env"`
	} `json:"session"`
	NonStream requestConfig   `json:"non_stream_request"`
	Stream    requestConfig   `json:"stream_request"`
	Baseline  json.RawMessage `json:"direct_upstream_baseline"`
	Quota     json.RawMessage `json:"quota"`
	Targets   json.RawMessage `json:"targets"`
	Metadata  json.RawMessage `json:"metadata"`
}

type privateJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

type protectedClient struct {
	baseURL     *url.URL
	accessToken string
	key         *ecdsa.PrivateKey
	publicJWK   dpop.PublicJWK
	http        *http.Client
}

type requestResult struct {
	Status         int
	ProblemCode    string
	FirstByte      bool
	Completed      bool
	TransportError bool
	Duration       time.Duration
}

type asyncRequest struct {
	clientRequestID string
	cancel          context.CancelFunc
	first           <-chan requestResult
	done            <-chan requestResult
}

func loadFailureConfig(path, dialAddress string) (loadConfig, *protectedClient, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 1<<20 {
		return loadConfig{}, nil, errors.New("failure load configuration is invalid")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return loadConfig{}, nil, errors.New("read failure load configuration")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var cfg loadConfig
	if err := decoder.Decode(&cfg); err != nil {
		return loadConfig{}, nil, errors.New("decode failure load configuration")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return loadConfig{}, nil, errors.New("failure load configuration has trailing data")
	}
	if cfg.SchemaVersion != 1 || !validRequestConfig(cfg.NonStream, false) || !validRequestConfig(cfg.Stream, true) {
		return loadConfig{}, nil, errors.New("failure load configuration contract is invalid")
	}
	base, err := url.Parse(cfg.Gateway.BaseURL)
	if err != nil || base.String() != "http://127.0.0.1:18080" || cfg.Gateway.ReadyPath != "/readyz" || cfg.Gateway.PID != 1 || cfg.Gateway.ProcessNameContains != "latchway" {
		return loadConfig{}, nil, errors.New("failure gateway origin is invalid")
	}
	dialHost, dialPort, err := net.SplitHostPort(dialAddress)
	dialIP := net.ParseIP(dialHost)
	if err != nil || dialPort != "18080" || dialIP == nil || dialIP.To4() == nil || !dialIP.IsPrivate() || dialHost != dialIP.String() {
		return loadConfig{}, nil, errors.New("failure gateway dial address must be one exact private address")
	}
	if !validEnvironmentName(cfg.Session.AccessTokenEnvironment) || !validEnvironmentName(cfg.Session.PrivateJWKEnvironment) {
		return loadConfig{}, nil, errors.New("failure session environment names are invalid")
	}
	accessToken := strings.TrimSpace(os.Getenv(cfg.Session.AccessTokenEnvironment))
	keyPath := strings.TrimSpace(os.Getenv(cfg.Session.PrivateJWKEnvironment))
	if len(accessToken) < 64 || len(accessToken) > 16<<10 || strings.ContainsAny(accessToken, "\r\n\x00") || keyPath == "" {
		return loadConfig{}, nil, errors.New("failure session material is invalid")
	}
	key, public, err := loadPrivateJWK(keyPath)
	if err != nil {
		return loadConfig{}, nil, err
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			if network != "tcp" && network != "tcp4" && network != "tcp6" {
				return nil, errors.New("failure gateway transport network is invalid")
			}
			return dialer.DialContext(ctx, "tcp", dialAddress)
		},
		MaxIdleConns: 128, MaxIdleConnsPerHost: 128, IdleConnTimeout: 30 * time.Second,
		ResponseHeaderTimeout: 3 * time.Minute,
	}
	return cfg, &protectedClient{
		baseURL: base, accessToken: accessToken, key: key, publicJWK: public,
		http: &http.Client{Transport: transport},
	}, nil
}

func validRequestConfig(value requestConfig, stream bool) bool {
	if strings.ToUpper(value.Method) != http.MethodPost || value.Path != "/v1/chat/completions" || value.ExpectedStatus != http.StatusOK || len(value.Body) == 0 || len(value.Body) > 1<<20 || !json.Valid(value.Body) {
		return false
	}
	if value.Headers["X-Latchway-Feature"] == "" || value.Headers["Content-Type"] != "application/json" {
		return false
	}
	var body struct {
		Stream bool `json:"stream"`
	}
	return json.Unmarshal(value.Body, &body) == nil && body.Stream == stream
}

func validEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if (character >= 'A' && character <= 'Z') || character == '_' || (index > 0 && character >= '0' && character <= '9') {
			continue
		}
		return false
	}
	return true
}

func loadPrivateJWK(path string) (*ecdsa.PrivateKey, dpop.PublicJWK, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 4096 {
		return nil, dpop.PublicJWK{}, errors.New("failure private JWK file is invalid")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return nil, dpop.PublicJWK{}, errors.New("read failure private JWK")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var value privateJWK
	if err := decoder.Decode(&value); err != nil || value.Kty != "EC" || value.Crv != "P-256" {
		return nil, dpop.PublicJWK{}, errors.New("failure private JWK is invalid")
	}
	x, err := decodeCoordinate(value.X)
	if err != nil {
		return nil, dpop.PublicJWK{}, err
	}
	y, err := decodeCoordinate(value.Y)
	if err != nil {
		return nil, dpop.PublicJWK{}, err
	}
	d, err := base64.RawURLEncoding.Strict().DecodeString(value.D)
	if err != nil || len(d) != 32 || base64.RawURLEncoding.EncodeToString(d) != value.D {
		return nil, dpop.PublicJWK{}, errors.New("failure private JWK scalar is invalid")
	}
	publicBytes := append([]byte{4}, append(append([]byte(nil), x...), y...)...)
	if _, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), publicBytes); err != nil {
		return nil, dpop.PublicJWK{}, errors.New("failure private JWK point is invalid")
	}
	privateKey, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), d)
	if err != nil {
		return nil, dpop.PublicJWK{}, errors.New("failure private JWK scalar is invalid")
	}
	derived, err := privateKey.PublicKey.Bytes()
	if err != nil || !bytes.Equal(derived, publicBytes) {
		return nil, dpop.PublicJWK{}, errors.New("failure private JWK public point mismatch")
	}
	return privateKey, dpop.PublicJWK{Kty: value.Kty, Crv: value.Crv, X: value.X, Y: value.Y}, nil
}

func decodeCoordinate(value string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("failure private JWK coordinate is invalid")
	}
	return decoded, nil
}

func (client *protectedClient) target(path string) *url.URL {
	target := *client.baseURL
	target.Path = strings.TrimRight(target.Path, "/") + path
	target.RawPath, target.RawQuery, target.Fragment = "", "", ""
	return &target
}

func (client *protectedClient) request(ctx context.Context, specification requestConfig, clientRequestID string, backend int) (*http.Request, error) {
	target := client.target(specification.Path)
	proof, err := client.proof(http.MethodPost, target)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target.String(), bytes.NewReader(specification.Body))
	if err != nil {
		return nil, err
	}
	for key, value := range specification.Headers {
		request.Header.Set(key, value)
	}
	request.Header.Set("Authorization", "DPoP "+client.accessToken)
	request.Header.Set("DPoP", proof)
	request.Header.Set("X-Latchway-Request-ID", clientRequestID)
	if backend > 0 {
		request.Header.Set("X-Latchway-Failure-Backend", fmt.Sprintf("%d", backend))
	}
	return request, nil
}

func (client *protectedClient) proof(method string, target *url.URL) (string, error) {
	header, err := json.Marshal(map[string]any{"typ": "dpop+jwt", "alg": "ES256", "jwk": client.publicJWK})
	if err != nil {
		return "", err
	}
	jti := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, jti); err != nil {
		return "", errors.New("generate failure DPoP identifier")
	}
	htu, err := dpop.NormalizeHTU(target)
	if err != nil {
		return "", errors.New("normalize failure DPoP target")
	}
	claims, err := json.Marshal(map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString(jti), "htm": method, "htu": htu,
		"iat": time.Now().UTC().Unix(), "ath": dpop.AccessTokenHash(client.accessToken),
	})
	if err != nil {
		return "", err
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	claimSegment := base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(headerSegment + "." + claimSegment))
	r, s, err := ecdsa.Sign(rand.Reader, client.key, digest[:])
	if err != nil {
		return "", errors.New("sign failure DPoP proof")
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return headerSegment + "." + claimSegment + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (client *protectedClient) execute(ctx context.Context, specification requestConfig, requestID string, backend int) requestResult {
	started := time.Now()
	request, err := client.request(ctx, specification, requestID, backend)
	if err != nil {
		return requestResult{TransportError: true, Duration: time.Since(started)}
	}
	response, err := client.http.Do(request)
	if err != nil {
		return requestResult{TransportError: true, Duration: time.Since(started)}
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil || len(body) > maximumResponseBytes {
		return requestResult{Status: response.StatusCode, TransportError: true, Duration: time.Since(started)}
	}
	return requestResult{
		Status: response.StatusCode, ProblemCode: stableProblemCode(response.StatusCode, body),
		Completed: true, Duration: time.Since(started),
	}
}

func (client *protectedClient) start(ctx context.Context, specification requestConfig, requestID string, backend int, stream bool) asyncRequest {
	requestContext, cancel := context.WithCancel(ctx)
	first := make(chan requestResult, 1)
	done := make(chan requestResult, 1)
	if !stream {
		go func() {
			result := client.execute(requestContext, specification, requestID, backend)
			first <- result
			done <- result
		}()
		return asyncRequest{clientRequestID: requestID, cancel: cancel, first: first, done: done}
	}
	go client.executeStream(requestContext, specification, requestID, backend, first, done)
	return asyncRequest{clientRequestID: requestID, cancel: cancel, first: first, done: done}
}

func (client *protectedClient) executeStream(ctx context.Context, specification requestConfig, requestID string, backend int, first chan<- requestResult, done chan<- requestResult) {
	started := time.Now()
	request, err := client.request(ctx, specification, requestID, backend)
	if err != nil {
		result := requestResult{TransportError: true, Duration: time.Since(started)}
		first <- result
		done <- result
		return
	}
	response, err := client.http.Do(request)
	if err != nil {
		result := requestResult{TransportError: true, Duration: time.Since(started)}
		first <- result
		done <- result
		return
	}
	if response.StatusCode != http.StatusOK || !strings.HasPrefix(response.Header.Get("Content-Type"), "text/event-stream") {
		body, _ := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
		_ = response.Body.Close()
		result := requestResult{Status: response.StatusCode, ProblemCode: stableProblemCode(response.StatusCode, body), Completed: true, Duration: time.Since(started)}
		first <- result
		done <- result
		return
	}
	reader := bufio.NewReaderSize(response.Body, 4096)
	firstErr := readFirstSSEEvent(reader)
	firstResult := requestResult{Status: response.StatusCode, FirstByte: firstErr == nil, TransportError: firstErr != nil, Duration: time.Since(started)}
	first <- firstResult
	if firstErr == nil {
		firstErr = readSSETerminal(reader)
	}
	closeErr := response.Body.Close()
	done <- requestResult{
		Status: response.StatusCode, FirstByte: firstResult.FirstByte,
		Completed:      firstErr == nil && closeErr == nil,
		TransportError: firstErr != nil || closeErr != nil,
		Duration:       time.Since(started),
	}
}

func readSSETerminal(reader *bufio.Reader) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 64<<10)
	total := 0
	for scanner.Scan() {
		total += len(scanner.Bytes()) + 1
		if total > maximumResponseBytes {
			return errors.New("failure SSE response exceeds bound")
		}
		if strings.TrimSpace(scanner.Text()) == "data: [DONE]" {
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return errors.New("failure SSE response ended before terminal event")
}

func readFirstSSEEvent(reader *bufio.Reader) error {
	total := 0
	hasData := false
	for total <= 64<<10 {
		line, err := reader.ReadString('\n')
		total += len(line)
		trimmed := strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		if strings.HasPrefix(trimmed, "data:") {
			hasData = true
		}
		if trimmed == "" {
			if !hasData {
				return errors.New("failure SSE event has no data field")
			}
			return nil
		}
		if err != nil {
			return err
		}
	}
	return errors.New("failure SSE event exceeds bound")
}

func stableProblemCode(status int, body []byte) string {
	if status < http.StatusBadRequest || len(body) == 0 {
		return ""
	}
	var problem struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &problem) != nil || len(problem.Code) < 2 || len(problem.Code) > 100 {
		return ""
	}
	for _, character := range problem.Code {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '_' {
			continue
		}
		return ""
	}
	return problem.Code
}
