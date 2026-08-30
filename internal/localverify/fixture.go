package localverify

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/buildinfo"
	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/database"
	"github.com/latchway/latchway/internal/dataplane"
	"github.com/latchway/latchway/internal/dpop"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/quota"
	"github.com/latchway/latchway/internal/requestidentity"
	"github.com/latchway/latchway/internal/secrets"
)

const (
	publicOrigin       = "https://gateway.local-verify.invalid"
	accessAudience     = "latchway-data-plane"
	oidcAudience       = "latchway-local-verify"
	providerModel      = "latchway-mock-model"
	configuredPrimary  = "https://primary.local-verify.invalid/v1"
	configuredFailure  = "https://failure.local-verify.invalid/v1"
	configuredFallback = "https://fallback.local-verify.invalid/v1"
	debugKeyID         = "local-verify-debug-key"
	providerTenant     = "local-verify"
	blockedPrompt      = "local-verify-concurrency-hold"
)

var schemaNamePattern = regexp.MustCompile(`^latchway_verify_[0-9a-f]{24}$`)

type tenant struct {
	organizationID string
	applicationID  string
	environmentID  string
	adminUserID    string
}

type fixture struct {
	databaseURL string
	schema      string
	adminPool   *pgxpool.Pool
	pool        *pgxpool.Pool

	tenant    tenant
	principal adminauth.Principal
	now       time.Time

	envelope           *secrets.EnvironmentMasterKey
	configurationStore *configuration.Store
	quotaRevisionID    string
	quotaRevisionETag  string

	oidc              *mockOIDC
	debugKey          ed25519.PrivateKey
	dpopKey           *ecdsa.PrivateKey
	dpopJKT           string
	accessToken       string
	nonStreamingProof string
	installationID    string
	applicationUserID string
	sessionGrantID    string

	providerCredential []byte
	providerCapture    *captureHandler
	failureCapture     *captureHandler
	fallbackCapture    *captureHandler
	providerServer     *privateServer
	failureServer      *privateServer
	fallbackServer     *privateServer

	clientHandler http.Handler
	dataHandler   http.Handler
	dataPlane     *dataplane.Handler
	quotaStore    *quota.Store

	cleanupOnce sync.Once
}

func newSchemaName() (string, error) {
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	name := "latchway_verify_" + hex.EncodeToString(random)
	if !schemaNamePattern.MatchString(name) {
		return "", errors.New("generated isolated schema name is invalid")
	}
	return name, nil
}

func (f *fixture) connect(ctx context.Context) error {
	pool, err := database.Open(ctx, f.databaseURL, 2)
	if err != nil {
		return err
	}
	f.adminPool = pool
	return nil
}

func (f *fixture) isolateAndMigrate(ctx context.Context) error {
	schema, err := newSchemaName()
	if err != nil {
		return err
	}
	if _, err := f.adminPool.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		return err
	}
	f.schema = schema
	pool, err := database.OpenInSchema(ctx, f.databaseURL, schema, 16)
	if err != nil {
		return err
	}
	f.pool = pool
	migrator := database.NewMigrator(pool)
	if err := migrator.Up(ctx); err != nil {
		return err
	}
	current, available, err := migrator.Status(ctx)
	if err != nil {
		return err
	}
	if current == 0 || current != available {
		return errors.New("isolated migration version is not current")
	}
	return nil
}

func (f *fixture) seedTenant(ctx context.Context) error {
	var err error
	f.tenant.organizationID, err = id.New(id.Organization)
	if err != nil {
		return err
	}
	f.tenant.applicationID, err = id.New(id.Application)
	if err != nil {
		return err
	}
	f.tenant.environmentID, err = id.New(id.Environment)
	if err != nil {
		return err
	}
	f.tenant.adminUserID, err = id.New(id.AdminUser)
	if err != nil {
		return err
	}
	membershipID, err := id.New(id.AdminMembership)
	if err != nil {
		return err
	}
	f.now = time.Now().UTC().Truncate(time.Second)
	createdAt := f.now.Add(-2 * time.Minute)
	statements := []struct {
		query string
		args  []any
	}{
		{`INSERT INTO organizations (organization_id, slug, display_name, status, created_at, updated_at) VALUES ($1, 'local-verify', 'Local verification', 'active', $2, $2)`, []any{f.tenant.organizationID, createdAt}},
		{`INSERT INTO applications (application_id, organization_id, slug, display_name, status, created_at, updated_at) VALUES ($1, $2, 'mobile-app', 'Mobile app', 'active', $3, $3)`, []any{f.tenant.applicationID, f.tenant.organizationID, createdAt}},
		{`INSERT INTO environments (environment_id, organization_id, application_id, slug, display_name, kind, status, created_at, updated_at) VALUES ($1, $2, $3, 'development', 'Development', 'development', 'active', $4, $4)`, []any{f.tenant.environmentID, f.tenant.organizationID, f.tenant.applicationID, createdAt}},
		{`INSERT INTO admin_users (admin_user_id, email, email_normalized, display_name, status, created_at, updated_at) VALUES ($1, 'local-verify@example.invalid', 'local-verify@example.invalid', 'Local verifier', 'active', $2, $2)`, []any{f.tenant.adminUserID, createdAt}},
		{`INSERT INTO admin_memberships (admin_membership_id, organization_id, admin_user_id, role, status, created_by_admin_user_id, created_at, updated_at) VALUES ($1, $2, $3, 'owner', 'active', $3, $4, $4)`, []any{membershipID, f.tenant.organizationID, f.tenant.adminUserID, createdAt}},
	}
	for _, statement := range statements {
		if _, err := f.pool.Exec(ctx, statement.query, statement.args...); err != nil {
			return err
		}
	}
	f.principal = adminauth.Principal{
		OrganizationID: f.tenant.organizationID, AdminUserID: f.tenant.adminUserID,
		Role: adminauth.RoleOwner, Method: adminauth.AuthenticationSession,
	}
	return nil
}

func (f *fixture) prepareCryptography() error {
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		return err
	}
	envelope, err := secrets.NewEnvironmentMasterKey(base64.StdEncoding.EncodeToString(master))
	if err != nil {
		return err
	}
	f.envelope = envelope
	_, debugPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f.debugKey = debugPrivate
	f.dpopKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	jwk := dpopJWK(f.dpopKey)
	f.dpopJKT, err = jwk.Thumbprint()
	if err != nil {
		return err
	}
	credentialEntropy := make([]byte, 24)
	if _, err := rand.Read(credentialEntropy); err != nil {
		return err
	}
	// Provider credentials cross an HTTP header boundary and therefore must be
	// printable ASCII even though the underlying secret is random.
	f.providerCredential = []byte(base64.RawURLEncoding.EncodeToString(credentialEntropy))
	clear(credentialEntropy)
	return nil
}

func (f *fixture) insertSecret(ctx context.Context, name string, plaintext []byte) error {
	recordID, err := id.New(id.SecretRecord)
	if err != nil {
		return err
	}
	encrypted, err := f.envelope.Encrypt(plaintext, secrets.AssociatedData{
		OrganizationID: f.tenant.organizationID, EnvironmentID: f.tenant.environmentID,
		SecretID: recordID, SecretVersion: 1, FormatVersion: 1,
	})
	if err != nil {
		return err
	}
	_, err = f.pool.Exec(ctx, `
		INSERT INTO secret_records (
			secret_record_id, organization_id, application_id, environment_id,
			name, version, encryption_format_version, algorithm,
			master_key_identifier, ciphertext, nonce, created_by_admin_user_id, created_at
		) VALUES ($1, $2, $3, $4, $5, 1, $6, 'aes-256-gcm', $7, $8, $9, $10, $11)
	`, recordID, f.tenant.organizationID, f.tenant.applicationID, f.tenant.environmentID,
		name, int16(encrypted.FormatVersion), encrypted.KeyID, encrypted.Ciphertext,
		encrypted.Nonce, f.tenant.adminUserID, f.now.Add(-time.Minute))
	return err
}

type mockOIDC struct {
	server     *httptest.Server
	privateKey *rsa.PrivateKey
	kid        string
	issuer     string
	jwksURL    string
	requests   int
	mu         sync.Mutex
}

func newMockOIDC() (*mockOIDC, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	issuer := &mockOIDC{privateKey: privateKey, kid: "local-verify-rs256"}
	server := httptest.NewTLSServer(http.HandlerFunc(issuer.serveHTTP))
	issuer.server = server
	issuer.issuer = server.URL
	issuer.jwksURL = server.URL + "/jwks"
	return issuer, nil
}

func (issuer *mockOIDC) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	issuer.mu.Lock()
	issuer.requests++
	issuer.mu.Unlock()
	writer.Header().Set("Cache-Control", "public, max-age=300")
	writer.Header().Set("Content-Type", "application/json")
	switch request.URL.Path {
	case "/.well-known/openid-configuration":
		_ = json.NewEncoder(writer).Encode(map[string]any{
			"issuer": issuer.issuer, "jwks_uri": issuer.jwksURL,
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	case "/jwks":
		_ = json.NewEncoder(writer).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": issuer.kid,
			"n": base64.RawURLEncoding.EncodeToString(issuer.privateKey.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(issuer.privateKey.E)).Bytes()),
		}}})
	default:
		http.NotFound(writer, request)
	}
}

func (issuer *mockOIDC) token(now time.Time) (string, error) {
	claims := jwt.MapClaims{
		"iss": issuer.issuer, "aud": oidcAudience, "sub": "local-verify-user",
		"tier": "pro", "iat": now.Add(-time.Minute).Unix(), "exp": now.Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = issuer.kid
	return token.SignedString(issuer.privateKey)
}

func (issuer *mockOIDC) requestCount() int {
	issuer.mu.Lock()
	defer issuer.mu.Unlock()
	return issuer.requests
}

type capturedRequest struct {
	Path    string
	Headers http.Header
	Body    []byte
}

type captureHandler struct {
	next         http.Handler
	blockMarker  string
	blockStarted chan struct{}
	blockRelease chan struct{}
	startOnce    sync.Once
	releaseOnce  sync.Once
	mu           sync.Mutex
	requests     []capturedRequest
	err          error
}

func (capture *captureHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(io.LimitReader(request.Body, 1<<20+1))
	if err != nil || len(body) > 1<<20 {
		capture.mu.Lock()
		capture.err = errors.New("provider capture body was invalid")
		capture.mu.Unlock()
		http.Error(writer, "invalid fixture body", http.StatusBadRequest)
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	capture.mu.Lock()
	capture.requests = append(capture.requests, capturedRequest{
		Path: request.URL.Path, Headers: request.Header.Clone(), Body: append([]byte(nil), body...),
	})
	capture.mu.Unlock()
	if capture.blockMarker != "" && bytes.Contains(body, []byte(capture.blockMarker)) {
		capture.startOnce.Do(func() {
			close(capture.blockStarted)
			<-capture.blockRelease
		})
	}
	capture.next.ServeHTTP(writer, request)
}

func (capture *captureHandler) snapshot() ([]capturedRequest, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	result := make([]capturedRequest, len(capture.requests))
	copy(result, capture.requests)
	return result, capture.err
}

func (capture *captureHandler) release() {
	if capture == nil || capture.blockRelease == nil {
		return
	}
	capture.releaseOnce.Do(func() { close(capture.blockRelease) })
}

type privateServer struct {
	baseURL  string
	server   *http.Server
	listener net.Listener
	done     chan error
}

func startPrivateServer(handler http.Handler) (*privateServer, error) {
	address, err := privateIPv4()
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(address, "0"))
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 2 * time.Second}
	done := make(chan error, 1)
	result := &privateServer{
		baseURL: "http://" + listener.Addr().String(), server: server,
		listener: listener, done: done,
	}
	go func() { done <- server.Serve(listener) }()
	return result, nil
}

func privateIPv4() (string, error) {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, candidate := range addresses {
		host, _, splitErr := net.ParseCIDR(candidate.String())
		if splitErr == nil && host != nil && host.To4() != nil && !host.IsLoopback() && host.IsPrivate() {
			return host.String(), nil
		}
	}
	return "", errors.New("no non-loopback private IPv4 address is available")
}

func (server *privateServer) close() error {
	if server == nil || server.server == nil {
		return nil
	}
	closeErr := server.server.Close()
	select {
	case serveErr := <-server.done:
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			return errors.Join(closeErr, serveErr)
		}
	case <-time.After(time.Second):
		return errors.New("private verification server did not stop")
	}
	return closeErr
}

func dpopJWK(privateKey *ecdsa.PrivateKey) dpop.PublicJWK {
	return dpop.PublicJWK{
		Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(privateKey.X.FillBytes(make([]byte, 32))),
		Y: base64.RawURLEncoding.EncodeToString(privateKey.Y.FillBytes(make([]byte, 32))),
	}
}

func signDPoP(privateKey *ecdsa.PrivateKey, method string, target *url.URL, now time.Time, label, accessToken string) (string, error) {
	htu, err := dpop.NormalizeHTU(target)
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]any{
		"typ": "dpop+jwt", "alg": "ES256", "jwk": dpopJWK(privateKey),
	})
	if err != nil {
		return "", err
	}
	jtiDigest := sha256.Sum256([]byte(label + "\x00" + now.Format(time.RFC3339Nano)))
	claims := map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString(jtiDigest[:]),
		"htm": method, "htu": htu, "iat": now.Unix(),
	}
	if accessToken != "" {
		claims["ath"] = dpop.AccessTokenHash(accessToken)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	claimsSegment := base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(headerSegment + "." + claimsSegment))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if err != nil {
		return "", err
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return headerSegment + "." + claimsSegment + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func withRequestIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx, err := requestidentity.NewContext(request.Context())
		if err != nil {
			http.Error(writer, "request identity unavailable", http.StatusInternalServerError)
			return
		}
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

type deadlineRecorder struct{ *httptest.ResponseRecorder }

func (*deadlineRecorder) SetWriteDeadline(time.Time) error { return nil }

func protectedHeaders(request *http.Request, proof string) {
	request.Host = "untrusted.local-verify.invalid"
	request.Header.Set("Forwarded", "host=attacker.invalid;proto=http")
	request.Header.Set("X-Forwarded-Host", "attacker.invalid")
	request.Header.Set("X-Forwarded-Proto", "http")
	request.Header.Set("X-Latchway-Protocol-Version", buildinfo.ProtocolVersion)
	request.Header.Set("X-Latchway-SDK", "react-native")
	request.Header.Set("X-Latchway-SDK-Version", "1.0.0")
	request.Header.Set("DPoP", proof)
}

func postJSON(handler http.Handler, path, proof string, body any) (*httptest.ResponseRecorder, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	protectedHeaders(request, proof)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response, nil
}

func postFeature(handler http.Handler, accessToken, proof, feature, clientRequestID string, body any) (*deadlineRecorder, error) {
	request, response, err := newFeatureRequest(accessToken, proof, feature, clientRequestID, body)
	if err != nil {
		return nil, err
	}
	handler.ServeHTTP(response, request)
	return response, nil
}

func newFeatureRequest(accessToken, proof, feature, clientRequestID string, body any) (*http.Request, *deadlineRecorder, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, nil, err
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(encoded))
	request.Header.Set("Content-Type", "application/json")
	protectedHeaders(request, proof)
	request.Header.Set("Authorization", "DPoP "+accessToken)
	request.Header.Set("X-Latchway-Feature", feature)
	request.Header.Set("X-Latchway-Request-ID", clientRequestID)
	request.Header.Set("Cookie", "provider-key=attacker")
	request.Header.Set("X-Api-Key", "attacker-provider-key")
	request.Header.Set("Anthropic-Api-Key", "attacker-anthropic-key")
	request.Header.Set("X-Untrusted-Provider-Header", "must-not-cross")
	response := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	return request, response, nil
}

func problemCode(response *httptest.ResponseRecorder) (string, error) {
	var document struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(response.Body).Decode(&document); err != nil {
		return "", err
	}
	return document.Code, nil
}

func requireStatus(response *httptest.ResponseRecorder, status int) error {
	if response == nil || response.Code != status {
		if response == nil {
			return errors.New("verification response is nil")
		}
		return fmt.Errorf("unexpected verification response status %d", response.Code)
	}
	return nil
}

func parseURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil, errors.New("verification URL is invalid")
	}
	return parsed, nil
}

func decodeJSON(response *httptest.ResponseRecorder, destination any) error {
	decoder := json.NewDecoder(response.Body)
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return errors.New("verification response contains trailing JSON")
	}
	return nil
}

func outputMaximum(body []byte) (int64, string, error) {
	var document struct {
		Model   string      `json:"model"`
		Maximum json.Number `json:"max_completion_tokens"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		return 0, "", err
	}
	maximum, err := strconv.ParseInt(document.Maximum.String(), 10, 64)
	return maximum, document.Model, err
}

func containsForbiddenProviderHeaders(headers http.Header) bool {
	for _, name := range []string{
		"Dpop", "Dpop-Nonce", "Cookie", "X-Api-Key", "Anthropic-Api-Key",
		"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
		"X-Latchway-Feature", "X-Latchway-Request-Id", "X-Untrusted-Provider-Header",
	} {
		if len(headers.Values(name)) != 0 {
			return true
		}
	}
	return false
}

func canonicalBearer(headers http.Header, credential []byte) bool {
	values := headers.Values("Authorization")
	return len(values) == 1 && values[0] == "Bearer "+string(credential) &&
		headers.Get("X-Provider-Tenant") == providerTenant
}

func debugKeyDocument(privateKey ed25519.PrivateKey) ([]byte, error) {
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("debug public key is invalid")
	}
	return json.Marshal(map[string]any{"version": 1, "keys": []any{map[string]any{
		"key_id": debugKeyID, "public_key": base64.RawURLEncoding.EncodeToString(publicKey),
	}}})
}

func (f *fixture) cleanup() error {
	var cleanupErr error
	f.cleanupOnce.Do(func() {
		if f.providerCapture != nil {
			f.providerCapture.release()
		}
		if f.dataPlane != nil {
			cleanupErr = errors.Join(cleanupErr, f.dataPlane.Close())
		}
		for _, server := range []*privateServer{f.providerServer, f.failureServer, f.fallbackServer} {
			cleanupErr = errors.Join(cleanupErr, server.close())
		}
		if f.oidc != nil && f.oidc.server != nil {
			f.oidc.server.Close()
		}
		if f.pool != nil {
			f.pool.Close()
		}
		if f.adminPool != nil && f.schema != "" && schemaNamePattern.MatchString(f.schema) {
			cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, err := f.adminPool.Exec(cleanupCtx, "DROP SCHEMA "+f.schema+" CASCADE")
			if err == nil {
				var exists bool
				err = f.adminPool.QueryRow(
					cleanupCtx,
					"SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)",
					f.schema,
				).Scan(&exists)
				if err == nil && exists {
					err = errors.New("isolated verification schema still exists after cleanup")
				}
			}
			cancel()
			cleanupErr = errors.Join(cleanupErr, err)
		}
		if f.adminPool != nil {
			f.adminPool.Close()
		}
		for index := range f.providerCredential {
			f.providerCredential[index] = 0
		}
	})
	return cleanupErr
}
