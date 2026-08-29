// latchway-load-provision creates an isolated load-test tenant through the
// canonical Admin and Client APIs. It writes credentials only to mode-0600
// files and never prints them.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/dpop"
)

const (
	maximumAPIResponseBytes = 1 << 20
	sdkName                 = "react-native"
	sdkVersion              = "1.0.0"
	clientPlatform          = "react_native_ios"
	identityIssuer          = "https://identity.load.invalid"
	identityAudience        = "latchway-load-client"
	debugKeyID              = "load-debug-key-v1"
	upstreamModel           = "fixture-model"

	loadOverheadSamples          = 1000
	loadOverheadWarmup           = 20
	loadP50GatewayOverheadMS     = 15
	loadP95GatewayOverheadMS     = 20
	loadP99GatewayOverheadMS     = 30
	loadNonStreamRPS             = 100
	loadNonStreamDurationSeconds = 60
	loadSSEConcurrency           = 500
	loadSSEHoldSeconds           = 60
	loadContentionAttempts       = 128
	loadContentionMaximum        = int64(64)
	loadLogicalRequestsMaximum   = int64(10_000)
	loadInputTokensMaximum       = int64(1_000_000)
	loadOutputTokensMaximum      = int64(100_000)
	loadTotalTokensMaximum       = int64(1_100_000)
	fixtureInputTokens           = int64(11)
	fixtureOutputTokens          = int64(7)
	fixtureTotalTokens           = int64(18)
	loadInputReservation         = int64(140)
	loadOutputReservation        = int64(8)
	loadTotalReservation         = int64(148)
)

type options struct {
	gatewayURL                  string
	upstreamURL                 string
	outputDir                   string
	localDockerImageID          string
	releaseOCIReference         string
	releaseOCIPlatformReference string
	commit                      string
	postgresIdentity            string
	postgresNetwork             string
	postgresCPUMilli            int64
	postgresMemory              int64
	postgresMemorySwap          int64
	postgresMaxConns            int
	gatewayDBPool               int
	bootstrapEnv                string
	adminPasswordEnv            string
}

type apiClient struct {
	baseURL *url.URL
	http    *http.Client
	cookies []*http.Cookie
	csrf    string
}

type resourceDocument struct {
	ID string `json:"id"`
}

type sessionDocument struct {
	OrganizationID string `json:"organization_id"`
}

type revisionDocument struct {
	ID string `json:"id"`
}

type validationReport struct {
	Valid  bool `json:"valid"`
	Issues []struct {
		Severity string `json:"severity"`
		Code     string `json:"code"`
		Path     string `json:"path"`
		Message  string `json:"message"`
	} `json:"issues"`
}

type challengeDocument struct {
	ChallengeID string `json:"challenge_id"`
	Attestation struct {
		Provider       string `json:"provider"`
		Mode           string `json:"mode"`
		ClientDataHash string `json:"client_data_hash"`
	} `json:"attestation"`
}

type grantDocument struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Installation struct {
		ID       string `json:"id"`
		Platform string `json:"platform"`
		DPoPJKT  string `json:"dpop_jkt"`
	} `json:"installation"`
	Trust struct {
		Provider string `json:"provider"`
		Level    string `json:"level"`
	} `json:"trust"`
}

type privateJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	D   string `json:"d"`
}

func main() {
	values := options{}
	flag.StringVar(&values.gatewayURL, "gateway-url", "http://127.0.0.1:8080", "isolated gateway origin")
	flag.StringVar(&values.upstreamURL, "upstream-base-url", "", "fixture base URL visible from the gateway")
	flag.StringVar(&values.outputDir, "output-dir", "", "empty private directory for generated session files")
	flag.StringVar(&values.localDockerImageID, "local-docker-image-id", "", "immutable local Docker gateway image ID")
	flag.StringVar(&values.releaseOCIReference, "release-oci-reference", "", "immutable release OCI index reference")
	flag.StringVar(&values.releaseOCIPlatformReference, "release-oci-platform-reference", "", "immutable executed release OCI platform-child reference")
	flag.StringVar(&values.commit, "commit", "", "exact core commit represented by the image")
	flag.StringVar(&values.postgresIdentity, "postgres-identity", "", "exact bounded PostgreSQL version/artifact identity")
	flag.StringVar(&values.postgresNetwork, "postgres-network", "", "exact bounded PostgreSQL network placement")
	flag.Int64Var(&values.postgresCPUMilli, "postgres-cpu-millicores", 0, "observed PostgreSQL CPU limit in millicores")
	flag.Int64Var(&values.postgresMemory, "postgres-memory-bytes", 0, "observed PostgreSQL memory limit in bytes")
	flag.Int64Var(&values.postgresMemorySwap, "postgres-memory-swap-bytes", 0, "observed PostgreSQL memory-plus-swap limit in bytes")
	flag.IntVar(&values.postgresMaxConns, "postgres-max-connections", 0, "observed PostgreSQL max_connections")
	flag.IntVar(&values.gatewayDBPool, "gateway-db-pool-max-connections", 0, "configured gateway DB pool maximum")
	flag.StringVar(&values.bootstrapEnv, "bootstrap-token-env", "LATCHWAY_LOAD_BOOTSTRAP_TOKEN", "environment variable containing the isolated bootstrap token")
	flag.StringVar(&values.adminPasswordEnv, "admin-password-env", "LATCHWAY_LOAD_ADMIN_PASSWORD", "environment variable containing the isolated owner password")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := run(ctx, values); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("isolated load tenant and DPoP session provisioned")
}

func run(ctx context.Context, values options) error {
	localImage := validLocalDockerImageID(values.localDockerImageID)
	releaseImage := validReleaseOCIReference(values.releaseOCIReference) &&
		validReleaseOCIReference(values.releaseOCIPlatformReference) &&
		releaseRepository(values.releaseOCIReference) == releaseRepository(values.releaseOCIPlatformReference) &&
		values.releaseOCIReference != values.releaseOCIPlatformReference
	if values.upstreamURL == "" || values.outputDir == "" || localImage == releaseImage || !validCommit(values.commit) {
		return errors.New("-upstream-base-url, -output-dir, one 40-character commit, and exactly one local image ID or release index/platform pair are required")
	}
	if !validEvidenceText(values.postgresIdentity) || !validEvidenceText(values.postgresNetwork) ||
		values.postgresCPUMilli < 1000 || values.postgresMemory < 1<<30 ||
		values.postgresMemorySwap < values.postgresMemory ||
		values.postgresMaxConns < 2 || values.postgresMaxConns > 500 ||
		values.gatewayDBPool < 2 || values.gatewayDBPool > values.postgresMaxConns {
		return errors.New("exact PostgreSQL identity/network/resources and a bounded gateway DB pool are required")
	}
	if !validEnvironmentName(values.bootstrapEnv) || !validEnvironmentName(values.adminPasswordEnv) {
		return errors.New("secret environment variable names are invalid")
	}
	bootstrapToken := os.Getenv(values.bootstrapEnv)
	adminPassword := os.Getenv(values.adminPasswordEnv)
	if !validSecret(bootstrapToken, 32, 4096) || !validSecret(adminPassword, 12, 1024) {
		return errors.New("isolated bootstrap token or owner password is empty or invalid")
	}
	if err := prepareOutputDir(values.outputDir); err != nil {
		return err
	}
	client, err := newAPIClient(values.gatewayURL)
	if err != nil {
		return err
	}
	fixtureURL, err := validateFixtureURL(values.upstreamURL)
	if err != nil {
		return err
	}
	if err := client.waitReady(ctx); err != nil {
		return err
	}

	identityPrivate, identityPublicPEM, err := identityKeyPair()
	if err != nil {
		return err
	}
	debugPublic, debugPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return errors.New("generate debug-attestation key")
	}
	debugDocument, err := json.Marshal(map[string]any{
		"version": 1,
		"keys": []any{map[string]any{
			"key_id":     debugKeyID,
			"public_key": base64.RawURLEncoding.EncodeToString(debugPublic),
		}},
	})
	if err != nil {
		return errors.New("encode debug-attestation public key")
	}

	organizationID, err := client.bootstrap(ctx, bootstrapToken, adminPassword)
	if err != nil {
		return err
	}
	applicationID, err := client.createApplication(ctx, organizationID)
	if err != nil {
		return err
	}
	environmentID, err := client.createEnvironment(ctx, applicationID)
	if err != nil {
		return err
	}
	if err := client.createSecret(ctx, environmentID, "identity-public-key", string(identityPublicPEM)); err != nil {
		return err
	}
	if err := client.createSecret(ctx, environmentID, "debug-attestation-public-keys", string(debugDocument)); err != nil {
		return err
	}
	configuration := loadConfiguration(fixtureURL.String(), fixtureURL.Hostname()+"/32")
	revisionID, err := client.activateConfiguration(ctx, environmentID, configuration)
	if err != nil {
		return err
	}

	dpopPrivate, dpopJWK, thumbprint, err := newDPoPKey()
	if err != nil {
		return err
	}
	identityToken, err := signIdentityToken(identityPrivate, time.Now().UTC())
	if err != nil {
		return err
	}
	grant, err := client.createSession(ctx, applicationID, identityToken, debugPrivate, dpopPrivate, thumbprint)
	if err != nil {
		return err
	}

	jwkBytes, err := json.MarshalIndent(dpopJWK, "", "  ")
	if err != nil {
		return errors.New("encode private DPoP JWK")
	}
	jwkBytes = append(jwkBytes, '\n')
	if err := writeExclusive(filepath.Join(values.outputDir, "dpop.jwk"), jwkBytes, 0o600); err != nil {
		return err
	}
	environmentFile := []byte("LATCHWAY_LOAD_ACCESS_TOKEN=" + grant.AccessToken + "\n" +
		"LATCHWAY_LOAD_DPOP_JWK_FILE=/evidence/runtime/dpop.jwk\n")
	if err := writeExclusive(filepath.Join(values.outputDir, "load.env"), environmentFile, 0o600); err != nil {
		return err
	}
	clear(environmentFile)

	loadConfig := buildLoadConfig(values, fixtureURL.String())
	configBytes, err := json.MarshalIndent(loadConfig, "", "  ")
	if err != nil {
		return errors.New("encode load configuration")
	}
	configBytes = append(configBytes, '\n')
	if err := writeExclusive(filepath.Join(values.outputDir, "load-config.json"), configBytes, 0o600); err != nil {
		return err
	}
	summary, err := json.MarshalIndent(map[string]any{
		"schema_version":                 1,
		"kind":                           "latchway_load_provision",
		"created_at":                     time.Now().UTC(),
		"commit":                         values.commit,
		"local_docker_image_id":          emptyAsNil(values.localDockerImageID),
		"release_oci_reference":          emptyAsNil(values.releaseOCIReference),
		"release_oci_platform_reference": emptyAsNil(values.releaseOCIPlatformReference),
		"organization_id":                organizationID,
		"application_id":                 applicationID,
		"environment_id":                 environmentID,
		"configuration_revision_id":      revisionID,
		"installation_id":                grant.Installation.ID,
		"platform":                       grant.Installation.Platform,
		"trust_provider":                 grant.Trust.Provider,
		"trust_level":                    grant.Trust.Level,
		"dpop_thumbprint":                thumbprint,
		"token_type":                     grant.TokenType,
	}, "", "  ")
	if err != nil {
		return errors.New("encode redacted provision summary")
	}
	summary = append(summary, '\n')
	return writeExclusive(filepath.Join(values.outputDir, "provision.json"), summary, 0o644)
}

func newAPIClient(raw string) (*apiClient, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("gateway URL must be one loopback HTTP origin")
	}
	host := parsed.Hostname()
	address := net.ParseIP(host)
	if host != "localhost" && (address == nil || !address.IsLoopback()) {
		return nil, errors.New("gateway URL must use localhost or an exact loopback address")
	}
	parsed.Path = ""
	return &apiClient{baseURL: parsed, http: &http.Client{Timeout: 30 * time.Second}}, nil
}

func validateFixtureURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "/v1" {
		return nil, errors.New("fixture base URL must be one explicit HTTP origin with the /v1 path")
	}
	address := net.ParseIP(parsed.Hostname())
	if address == nil || address.IsLoopback() || !address.IsPrivate() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return nil, errors.New("fixture URL must use the exact RFC1918 IP assigned inside the isolated container network")
	}
	if parsed.Port() == "" {
		return nil, errors.New("fixture URL must include its explicit isolated-network port")
	}
	return parsed, nil
}

func (client *apiClient) waitReady(ctx context.Context) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.endpoint("/readyz"), nil)
		if err == nil {
			response, callErr := client.http.Do(request)
			if callErr == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("gateway did not become ready before the provisioning deadline")
		case <-ticker.C:
		}
	}
}

func (client *apiClient) bootstrap(ctx context.Context, token, password string) (string, error) {
	var document sessionDocument
	response, err := client.doJSON(ctx, http.MethodPost, "/admin/v1/auth/bootstrap", map[string]any{
		"bootstrap_token":   token,
		"organization_slug": "load",
		"organization_name": "Isolated Load Evidence",
		"email":             "load-owner@example.invalid",
		"display_name":      "Load Evidence Owner",
		"password":          password,
	}, false, false, "", http.StatusCreated, &document)
	if err != nil {
		return "", fmt.Errorf("bootstrap isolated owner: %w", err)
	}
	client.cookies = response.Cookies()
	client.csrf = response.Header.Get("X-CSRF-Token")
	if document.OrganizationID == "" || client.csrf == "" || !hasCookie(client.cookies, "__Host-latchway_admin") {
		return "", errors.New("bootstrap response omitted tenant or secure session state")
	}
	return document.OrganizationID, nil
}

func (client *apiClient) createApplication(ctx context.Context, organizationID string) (string, error) {
	var document resourceDocument
	_, err := client.doJSON(ctx, http.MethodPost, "/admin/v1/applications", map[string]any{
		"organization_id": organizationID,
		"slug":            "load-app",
		"display_name":    "Load Test Application",
	}, true, true, "", http.StatusCreated, &document)
	if err != nil || document.ID == "" {
		return "", fmt.Errorf("create isolated application: %w", firstError(err, errors.New("application response omitted id")))
	}
	return document.ID, nil
}

func (client *apiClient) createEnvironment(ctx context.Context, applicationID string) (string, error) {
	var document resourceDocument
	_, err := client.doJSON(ctx, http.MethodPost, "/admin/v1/applications/"+applicationID+"/environments", map[string]any{
		"slug":         "development",
		"display_name": "Load Test Development",
		"kind":         "development",
	}, true, true, "", http.StatusCreated, &document)
	if err != nil || document.ID == "" {
		return "", fmt.Errorf("create isolated environment: %w", firstError(err, errors.New("environment response omitted id")))
	}
	return document.ID, nil
}

func (client *apiClient) createSecret(ctx context.Context, environmentID, name, value string) error {
	var document resourceDocument
	_, err := client.doJSON(ctx, http.MethodPost, "/admin/v1/secrets", map[string]any{
		"environment_id": environmentID,
		"name":           name,
		"value":          value,
	}, true, true, "", http.StatusCreated, &document)
	if err != nil {
		return fmt.Errorf("create %s secret: %w", name, err)
	}
	if document.ID == "" {
		return fmt.Errorf("create %s secret: response omitted id", name)
	}
	return nil
}

func (client *apiClient) activateConfiguration(ctx context.Context, environmentID string, document any) (string, error) {
	var revision revisionDocument
	response, err := client.doJSON(ctx, http.MethodPost, "/admin/v1/environments/"+environmentID+"/config-revisions", map[string]any{
		"document":    document,
		"description": "isolated v1 load gates",
	}, true, true, "", http.StatusCreated, &revision)
	if err != nil {
		return "", fmt.Errorf("create load configuration: %w", err)
	}
	etag := response.Header.Get("ETag")
	if revision.ID == "" || !validETag(etag) {
		return "", errors.New("configuration draft omitted id or strong ETag")
	}
	var report validationReport
	_, err = client.doJSON(ctx, http.MethodPost, "/admin/v1/config-revisions/"+revision.ID+"/validate", nil, true, true, "", http.StatusOK, &report)
	if err != nil {
		return "", fmt.Errorf("validate load configuration: %w", err)
	}
	if !report.Valid {
		return "", fmt.Errorf("load configuration validation failed: %s", summarizeIssues(report))
	}
	var active revisionDocument
	_, err = client.doJSON(ctx, http.MethodPost, "/admin/v1/config-revisions/"+revision.ID+"/activate", nil, true, true, etag, http.StatusOK, &active)
	if err != nil {
		return "", fmt.Errorf("activate load configuration: %w", err)
	}
	if active.ID != revision.ID {
		return "", errors.New("configuration activation returned a mismatched revision")
	}
	return revision.ID, nil
}

func (client *apiClient) createSession(ctx context.Context, applicationID, identityToken string, debugPrivate ed25519.PrivateKey, dpopPrivate *ecdsa.PrivateKey, thumbprint string) (grantDocument, error) {
	now := time.Now().UTC()
	challengeTarget, _ := url.Parse(client.endpoint("/client/v1/session-challenges"))
	challengeProof, err := signDPoP(dpopPrivate, http.MethodPost, challengeTarget, now, "")
	if err != nil {
		return grantDocument{}, err
	}
	var challenge challengeDocument
	if _, err := client.doProtectedJSON(ctx, "/client/v1/session-challenges", challengeProof, map[string]any{
		"application_id":    applicationID,
		"environment":       "development",
		"identity_provider": "custom",
		"identity_token":    identityToken,
		"platform":          clientPlatform,
		"sdk_version":       sdkVersion,
	}, http.StatusCreated, &challenge); err != nil {
		return grantDocument{}, fmt.Errorf("create DPoP session challenge: %w", err)
	}
	bindingBytes, err := base64.RawURLEncoding.Strict().DecodeString(challenge.Attestation.ClientDataHash)
	if err != nil || len(bindingBytes) != sha256.Size || challenge.ChallengeID == "" || challenge.Attestation.Provider != "debug" || challenge.Attestation.Mode != "required" {
		return grantDocument{}, errors.New("session challenge returned invalid debug-attestation binding")
	}
	var binding [sha256.Size]byte
	copy(binding[:], bindingBytes)
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second).Unix()
	signature := ed25519.Sign(debugPrivate, attestation.DebugSigningMessage(binding, expiresAt))
	exchangeTarget, _ := url.Parse(client.endpoint("/client/v1/sessions"))
	exchangeProof, err := signDPoP(dpopPrivate, http.MethodPost, exchangeTarget, time.Now().UTC(), "")
	if err != nil {
		return grantDocument{}, err
	}
	var grant grantDocument
	if _, err := client.doProtectedJSON(ctx, "/client/v1/sessions", exchangeProof, map[string]any{
		"challenge_id": challenge.ChallengeID,
		"attestation": map[string]any{
			"provider": "debug",
			"evidence": map[string]any{
				"key_id":       debugKeyID,
				"binding_hash": challenge.Attestation.ClientDataHash,
				"expires_at":   expiresAt,
				"signature":    base64.RawURLEncoding.EncodeToString(signature),
			},
		},
		"installation": map[string]any{"app_version": "1.0.0"},
	}, http.StatusCreated, &grant); err != nil {
		return grantDocument{}, fmt.Errorf("exchange DPoP session challenge: %w", err)
	}
	if grant.TokenType != "DPoP" || !validSecret(grant.AccessToken, 64, 16<<10) || grant.Installation.ID == "" ||
		grant.Installation.Platform != clientPlatform || grant.Installation.DPoPJKT != thumbprint ||
		grant.Trust.Provider != "debug" || grant.Trust.Level != "debug" {
		return grantDocument{}, errors.New("session grant violated the expected DPoP/debug trust binding")
	}
	return grant, nil
}

func (client *apiClient) doJSON(ctx context.Context, method, path string, body any, authenticated, csrf bool, etag string, expected int, output any) (*http.Response, error) {
	encoded, err := encodeBody(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, client.endpoint(path), bytes.NewReader(encoded))
	if err != nil {
		clear(encoded)
		return nil, errors.New("construct API request")
	}
	request.Header.Set("Accept", "application/json, application/problem+json")
	request.Header.Set("Origin", strings.TrimSuffix(client.baseURL.String(), "/"))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		for _, cookie := range client.cookies {
			request.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
		}
	}
	if csrf {
		request.Header.Set("X-CSRF-Token", client.csrf)
	}
	if etag != "" {
		request.Header.Set("If-Match", etag)
	}
	response, callErr := client.call(request, expected, output)
	clear(encoded)
	return response, callErr
}

func (client *apiClient) doProtectedJSON(ctx context.Context, path, proof string, body any, expected int, output any) (*http.Response, error) {
	encoded, err := encodeBody(body)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint(path), bytes.NewReader(encoded))
	if err != nil {
		clear(encoded)
		return nil, errors.New("construct protected client request")
	}
	request.Header.Set("Accept", "application/json, application/problem+json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("DPoP", proof)
	request.Header.Set("X-Latchway-Protocol-Version", "1")
	request.Header.Set("X-Latchway-SDK", sdkName)
	request.Header.Set("X-Latchway-SDK-Version", sdkVersion)
	response, callErr := client.call(request, expected, output)
	clear(encoded)
	return response, callErr
}

func (client *apiClient) call(request *http.Request, expected int, output any) (*http.Response, error) {
	response, err := client.http.Do(request)
	if err != nil {
		return nil, errors.New("call isolated gateway API")
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumAPIResponseBytes+1))
	if err != nil || len(body) > maximumAPIResponseBytes {
		return nil, errors.New("gateway API response exceeded its evidence bound")
	}
	if response.StatusCode != expected {
		var problem struct {
			Code   string `json:"code"`
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(body, &problem)
		if problem.Code != "" {
			return nil, fmt.Errorf("gateway API returned HTTP %d (%s): %s", response.StatusCode, problem.Code, boundedDetail(problem.Detail))
		}
		return nil, fmt.Errorf("gateway API returned HTTP %d", response.StatusCode)
	}
	if output != nil {
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err := decoder.Decode(output); err != nil {
			return nil, errors.New("decode gateway API response")
		}
	}
	return response, nil
}

func (client *apiClient) endpoint(path string) string {
	copy := *client.baseURL
	copy.Path = path
	copy.RawPath = ""
	copy.RawQuery = ""
	copy.Fragment = ""
	return copy.String()
}

func loadConfiguration(fixtureBaseURL, fixtureCIDR string) map[string]any {
	return map[string]any{
		"apiVersion": "latchway.dev/v1alpha1",
		"kind":       "EnvironmentConfig",
		"metadata": map[string]any{
			"organization": "load",
			"application":  "load-app",
			"environment":  "development",
		},
		"spec": map[string]any{
			"identityProviders": []any{map[string]any{
				"id":                       "custom",
				"type":                     "custom_jwt",
				"issuer":                   identityIssuer,
				"audiences":                []any{identityAudience},
				"allowedAlgorithms":        []any{"RS256"},
				"staticPublicKeySecretRef": "secret/identity-public-key",
				"subjectClaim":             "sub",
				"clockSkewSeconds":         30,
			}},
			"attestationPolicies": []any{map[string]any{
				"id":     "native",
				"maxAge": "10m",
				"platforms": map[string]any{
					clientPlatform: map[string]any{
						"provider":          "debug",
						"mode":              "required",
						"minimumTrustLevel": "debug",
						"secretRef":         "secret/debug-attestation-public-keys",
					},
				},
			}},
			"upstreams": []any{map[string]any{
				"id":                         "fixture",
				"type":                       "openai_compatible",
				"baseUrl":                    fixtureBaseURL,
				"dangerousAllowInsecureHttp": true,
				"authentication":             map[string]any{"type": "none"},
				"timeouts": map[string]any{
					"connect": "2s", "firstByte": "30s", "idle": "2m", "total": "3m",
				},
				"destinationPolicy": map[string]any{
					"allowedPorts":         []any{19090},
					"allowRedirects":       false,
					"allowPrivateNetworks": true,
					"allowedCidrs":         []any{fixtureCIDR},
					"dnsPinning":           true,
				},
			}},
			"inputAccountingProfiles": []any{map[string]any{
				"id":                             "fixture-bytes",
				"protocol":                       "openai_chat",
				"method":                         "utf8_byte_bpe_declared_framing_v1",
				"physicalModel":                  upstreamModel,
				"maximumFramingTokensPerRequest": 8,
				"maximumFramingTokensPerMessage": 4,
				"maximumContextTokens":           4096,
			}},
			"models": []any{map[string]any{
				"id":                 "load-model",
				"upstream":           "fixture",
				"upstreamModel":      upstreamModel,
				"inputAccountingRef": "fixture-bytes",
				"capabilities":       []any{"openai_chat"},
			}},
			"limitPlans": []any{
				map[string]any{
					"id": "load",
					"limits": []any{
						calendarLimit("logical_requests", loadLogicalRequestsMaximum),
						calendarLimit("input_tokens", loadInputTokensMaximum),
						calendarLimit("output_tokens", loadOutputTokensMaximum),
						calendarLimit("total_tokens", loadTotalTokensMaximum),
					},
				},
				map[string]any{
					"id": "stream-load",
					"limits": []any{map[string]any{
						"metric":    "concurrent_streams",
						"algorithm": "concurrency",
						"scope":     []any{"feature", "user"},
						"maximum":   600,
						"hard":      true,
					}},
				},
				map[string]any{
					"id":     "contention",
					"limits": []any{calendarLimit("logical_requests", loadContentionMaximum)},
				},
			},
			"features": []any{
				loadFeature("load", "load"),
				loadFeature("stream-load", "stream-load"),
				loadFeature("contention", "contention"),
			},
		},
	}
}

func calendarLimit(metric string, maximum int64) map[string]any {
	return map[string]any{
		"metric":    metric,
		"algorithm": "calendar",
		"scope":     []any{"feature", "user"},
		"window":    "1d",
		"maximum":   maximum,
		"hard":      true,
	}
}

func loadFeature(id, plan string) map[string]any {
	return map[string]any{
		"id":                id,
		"protocol":          "openai_chat",
		"attestationPolicy": "native",
		"access":            map[string]any{"expression": "principal.authenticated"},
		"limitPlan":         map[string]any{"expression": "'" + plan + "'"},
		"output":            map[string]any{"defaultMaximumTokens": 8, "absoluteMaximumTokens": 8},
		"routes": []any{map[string]any{
			"id":       "fixture",
			"when":     "true",
			"model":    "load-model",
			"priority": 10,
		}},
	}
}

func buildLoadConfig(values options, fixtureBaseURL string) map[string]any {
	requestHeaders := map[string]any{
		"Content-Type":                "application/json",
		"X-Latchway-Protocol-Version": "1",
		"X-Latchway-SDK":              sdkName,
		"X-Latchway-SDK-Version":      sdkVersion,
	}
	request := func(feature, prompt string, stream bool) map[string]any {
		headers := make(map[string]any, len(requestHeaders)+1)
		for key, value := range requestHeaders {
			headers[key] = value
		}
		headers["X-Latchway-Feature"] = feature
		return map[string]any{
			"method":  "POST",
			"path":    "/v1/chat/completions",
			"headers": headers,
			"body": map[string]any{
				"model":                 "load-model",
				"messages":              []any{map[string]any{"role": "user", "content": prompt}},
				"stream":                stream,
				"max_completion_tokens": 8,
			},
			"expected_status": 200,
		}
	}
	return map[string]any{
		"schema_version": 1,
		"environment": map[string]any{
			"label":                           "self-contained-local-v1",
			"cpu":                             "2 vCPU enforced by Docker NanoCPUs=2000000000",
			"memory":                          "2 GiB enforced by Docker Memory=2147483648",
			"postgresql":                      values.postgresIdentity,
			"postgresql_cpu_millicores":       values.postgresCPUMilli,
			"postgresql_memory_bytes":         values.postgresMemory,
			"postgresql_memory_swap_bytes":    values.postgresMemorySwap,
			"postgresql_max_connections":      values.postgresMaxConns,
			"postgresql_network":              values.postgresNetwork,
			"gateway_db_pool_max_connections": values.gatewayDBPool,
			"body_logging_disabled":           true,
			"warm_configuration_cache":        true,
		},
		"gateway": map[string]any{
			"base_url":              values.gatewayURL,
			"ready_path":            "/readyz",
			"pid":                   1,
			"process_name_contains": "latchway",
		},
		"session": map[string]any{
			"access_token_env":     "LATCHWAY_LOAD_ACCESS_TOKEN",
			"private_jwk_file_env": "LATCHWAY_LOAD_DPOP_JWK_FILE",
		},
		"non_stream_request": request("load", "bounded load fixture", false),
		"stream_request":     request("stream-load", "bounded streaming fixture", true),
		"direct_upstream_baseline": map[string]any{
			"url":     fixtureBaseURL + "/chat/completions",
			"headers": map[string]any{"Content-Type": "application/json"},
			"body": map[string]any{
				"model":                 upstreamModel,
				"messages":              []any{map[string]any{"role": "user", "content": "bounded load fixture"}},
				"stream":                false,
				"max_completion_tokens": 8,
			},
			"expected_status": 200,
		},
		"quota": map[string]any{
			"non_stream_snapshot_path":   "/client/v1/features/load/quota",
			"stream_snapshot_path":       "/client/v1/features/stream-load/quota",
			"contention_snapshot_path":   "/client/v1/features/contention/quota",
			"non_stream_terminal_limits": loadTerminalLimits(),
			"stream_terminal_limits": []any{map[string]any{
				"metric": "concurrent_streams", "maximum": 600, "used": 0,
				"reserved": 0, "remaining": 600, "hard": true,
			}},
			"contention_request":  request("contention", "quota contention fixture", false),
			"contention_metric":   "logical_requests",
			"contention_attempts": loadContentionAttempts,
			"denial_status":       429,
			"denial_problem_code": "quota_exceeded",
			"fixture": map[string]any{
				"protected_preflight_requests":      1,
				"overhead_warmup_requests":          loadOverheadWarmup,
				"overhead_sample_requests":          loadOverheadSamples,
				"non_stream_load_requests":          loadNonStreamRPS * loadNonStreamDurationSeconds,
				"settled_input_tokens_per_request":  fixtureInputTokens,
				"settled_output_tokens_per_request": fixtureOutputTokens,
				"settled_total_tokens_per_request":  fixtureTotalTokens,
				"input_reservation_per_request":     loadInputReservation,
				"output_reservation_per_request":    loadOutputReservation,
				"total_reservation_per_request":     loadTotalReservation,
			},
		},
		"targets": map[string]any{
			"overhead_samples":                           loadOverheadSamples,
			"overhead_warmup":                            loadOverheadWarmup,
			"p50_gateway_overhead_ms":                    loadP50GatewayOverheadMS,
			"p95_gateway_overhead_ms":                    loadP95GatewayOverheadMS,
			"p99_gateway_overhead_ms":                    loadP99GatewayOverheadMS,
			"non_stream_rps":                             loadNonStreamRPS,
			"non_stream_duration_seconds":                loadNonStreamDurationSeconds,
			"maximum_schedule_lag_ms":                    25,
			"sse_concurrency":                            loadSSEConcurrency,
			"sse_hold_seconds":                           loadSSEHoldSeconds,
			"maximum_stream_memory_growth_mib":           128,
			"maximum_stream_memory_slope_mib_per_minute": 5,
			"idle_warmup_seconds":                        10,
			"idle_memory_mib":                            256,
			"request_timeout_seconds":                    120,
		},
		"metadata": loadEvidenceMetadata(values),
	}
}

func loadEvidenceMetadata(values options) map[string]any {
	metadata := map[string]any{
		"deployment": "isolated internal Docker network; gateway --cpus=2 --memory=2g --memory-swap=2g",
		"operator":   "scripts/run-local-load-gates.sh",
	}
	if values.localDockerImageID != "" {
		metadata["local_docker_image_id"] = values.localDockerImageID
		return metadata
	}
	metadata["release_oci_reference"] = values.releaseOCIReference
	metadata["release_oci_platform_reference"] = values.releaseOCIPlatformReference
	metadata["operator"] = ".github/workflows/release-load-evidence.yml"
	return metadata
}

func emptyAsNil(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func loadTerminalLimits() []any {
	requestCount := int64(1 + loadOverheadWarmup + loadOverheadSamples +
		loadNonStreamRPS*loadNonStreamDurationSeconds)
	return []any{
		terminalLimit("logical_requests", loadLogicalRequestsMaximum, requestCount),
		terminalLimit("input_tokens", loadInputTokensMaximum, requestCount*fixtureInputTokens),
		terminalLimit("output_tokens", loadOutputTokensMaximum, requestCount*fixtureOutputTokens),
		terminalLimit("total_tokens", loadTotalTokensMaximum, requestCount*fixtureTotalTokens),
	}
}

func terminalLimit(metric string, maximum, used int64) map[string]any {
	return map[string]any{
		"metric": metric, "maximum": maximum, "used": used,
		"reserved": 0, "remaining": maximum - used, "hard": true,
	}
}

func identityKeyPair() (*rsa.PrivateKey, []byte, error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, errors.New("generate identity signing key")
	}
	der, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		return nil, nil, errors.New("marshal identity public key")
	}
	return private, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func signIdentityToken(private *rsa.PrivateKey, now time.Time) (string, error) {
	claims := jwt.MapClaims{
		"iss": identityIssuer,
		"aud": identityAudience,
		"sub": "isolated-load-user",
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(15 * time.Minute).Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(private)
	if err != nil {
		return "", errors.New("sign isolated identity credential")
	}
	return token, nil
}

func newDPoPKey() (*ecdsa.PrivateKey, privateJWK, string, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, privateJWK{}, "", errors.New("generate DPoP key")
	}
	value := privateJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(private.X.FillBytes(make([]byte, 32))),
		Y:   base64.RawURLEncoding.EncodeToString(private.Y.FillBytes(make([]byte, 32))),
		D:   base64.RawURLEncoding.EncodeToString(private.D.FillBytes(make([]byte, 32))),
	}
	thumbprint, err := (dpop.PublicJWK{Kty: value.Kty, Crv: value.Crv, X: value.X, Y: value.Y}).Thumbprint()
	if err != nil {
		return nil, privateJWK{}, "", errors.New("compute DPoP thumbprint")
	}
	return private, value, thumbprint, nil
}

func signDPoP(private *ecdsa.PrivateKey, method string, target *url.URL, now time.Time, accessToken string) (string, error) {
	header, err := json.Marshal(map[string]any{
		"typ": "dpop+jwt",
		"alg": "ES256",
		"jwk": dpop.PublicJWK{
			Kty: "EC", Crv: "P-256",
			X: base64.RawURLEncoding.EncodeToString(private.X.FillBytes(make([]byte, 32))),
			Y: base64.RawURLEncoding.EncodeToString(private.Y.FillBytes(make([]byte, 32))),
		},
	})
	if err != nil {
		return "", errors.New("encode DPoP header")
	}
	jti := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, jti); err != nil {
		return "", errors.New("generate DPoP identifier")
	}
	htu, err := dpop.NormalizeHTU(target)
	if err != nil {
		return "", errors.New("normalize DPoP target")
	}
	claims := map[string]any{
		"jti": base64.RawURLEncoding.EncodeToString(jti),
		"htm": strings.ToUpper(method),
		"htu": htu,
		"iat": now.Unix(),
	}
	if accessToken != "" {
		claims["ath"] = dpop.AccessTokenHash(accessToken)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", errors.New("encode DPoP claims")
	}
	headerSegment := base64.RawURLEncoding.EncodeToString(header)
	claimsSegment := base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(headerSegment + "." + claimsSegment))
	r, s, err := ecdsa.Sign(rand.Reader, private, digest[:])
	if err != nil {
		return "", errors.New("sign DPoP proof")
	}
	signature := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return headerSegment + "." + claimsSegment + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func encodeBody(value any) ([]byte, error) {
	if value == nil {
		return nil, nil
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("encode bounded API request")
	}
	if len(encoded) > 1<<20 {
		return nil, errors.New("API request exceeds 1 MiB")
	}
	return encoded, nil
}

func prepareOutputDir(path string) error {
	if !filepath.IsAbs(path) {
		return errors.New("output directory must be absolute")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output path must be one real directory")
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("protect output directory: %w", err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if len(entries) != 0 {
		return errors.New("output directory must be empty")
	}
	return nil
}

func writeExclusive(path string, contents []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", filepath.Base(path), err)
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync %s: %w", filepath.Base(path), err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close %s: %w", filepath.Base(path), err)
	}
	return nil
}

func validLocalDockerImageID(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	digest := strings.TrimPrefix(value, "sha256:")
	if strings.ToLower(digest) != digest {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func validReleaseOCIReference(value string) bool {
	const prefix = "ghcr.io/latchway/latchway@sha256:"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+sha256.Size*2 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, prefix))
	return err == nil
}

func releaseRepository(value string) string {
	repository, _, _ := strings.Cut(value, "@sha256:")
	return repository
}

func validCommit(value string) bool {
	if len(value) != 40 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
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

func validSecret(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && !strings.ContainsAny(value, "\r\n\x00")
}

func validEvidenceText(value string) bool {
	return len(value) >= 2 && len(value) <= 512 && strings.TrimSpace(value) == value &&
		!strings.ContainsAny(value, "\r\n\x00")
}

func validETag(value string) bool {
	return len(value) >= 3 && len(value) <= 256 && value[0] == '"' && value[len(value)-1] == '"' &&
		!strings.HasPrefix(value, "W/") && !strings.ContainsAny(value, "\r\n,")
}

func hasCookie(cookies []*http.Cookie, name string) bool {
	for _, cookie := range cookies {
		if cookie.Name == name && cookie.Value != "" {
			return true
		}
	}
	return false
}

func summarizeIssues(report validationReport) string {
	parts := make([]string, 0, len(report.Issues))
	for index, issue := range report.Issues {
		if index == 8 {
			parts = append(parts, "additional issues omitted")
			break
		}
		parts = append(parts, issue.Code+" at "+issue.Path)
	}
	if len(parts) == 0 {
		return "validator returned no issue details"
	}
	return strings.Join(parts, "; ")
}

func boundedDetail(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 256 {
		value = value[:256] + "..."
	}
	return value
}

func firstError(primary, fallback error) error {
	if primary != nil {
		return primary
	}
	return fallback
}
