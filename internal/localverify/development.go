package localverify

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/latchway/latchway/internal/adminapi"
	"github.com/latchway/latchway/internal/adminauth"
	"github.com/latchway/latchway/internal/attestation"
	"github.com/latchway/latchway/internal/config"
	"github.com/latchway/latchway/internal/id"
	"github.com/latchway/latchway/internal/secrets"
	"github.com/latchway/latchway/internal/server"
	"github.com/latchway/latchway/internal/telemetry"
	"github.com/latchway/latchway/internal/weborigin"
)

const developmentConsoleEmail = "local-verify@example.invalid"

// DevelopmentConfig starts one foreground, isolated development deployment.
// Its generated PostgreSQL schema is retained while the process runs and
// dropped on every normal, canceled, or failed exit.
type DevelopmentConfig struct {
	DatabaseURL   string
	ListenAddress string
	BrowserOrigin string
	Logger        *slog.Logger
	OnReady       func(DevelopmentInfo) error
}

// DevelopmentInfo is the exact copyable contract shared by every client
// quickstart. ConsolePassword is an ephemeral local credential printed once by
// the CLI; callers must not log the value through any other path.
type DevelopmentInfo struct {
	GatewayURL             string `json:"gateway_url"`
	ApplicationID          string `json:"application_id"`
	Environment            string `json:"environment"`
	Feature                string `json:"feature"`
	Model                  string `json:"model"`
	BrowserOrigin          string `json:"browser_origin"`
	IdentityTokenURL       string `json:"identity_token_url"`
	AttestationEvidenceURL string `json:"attestation_evidence_url"`
	ConsoleURL             string `json:"console_url"`
	ConsoleEmail           string `json:"console_email"`
	ConsolePassword        string `json:"console_password"`
	IOSBundleIdentifier    string `json:"ios_bundle_identifier"`
	AndroidPackageName     string `json:"android_package_name"`
	ReactNativeBundleID    string `json:"react_native_bundle_identifier"`
	ReactNativePackageName string `json:"react_native_package_name"`
}

// RunDevelopment serves a deterministic mock identity, challenge-bound debug
// signer, mock upstream, gateway, Admin API, and embedded Console on one exact
// loopback origin until the caller cancels the context.
func RunDevelopment(parent context.Context, development DevelopmentConfig) (runErr error) {
	if parent == nil {
		return errors.New("local development requires a context")
	}
	if strings.TrimSpace(development.DatabaseURL) == "" || strings.TrimSpace(development.DatabaseURL) != development.DatabaseURL {
		return errors.New("local development requires a PostgreSQL database URL")
	}
	listenHost, _, err := validateDevelopmentListenAddress(development.ListenAddress)
	if err != nil {
		return err
	}
	if !weborigin.LoopbackHTTP(development.BrowserOrigin) {
		return errors.New("local development browser origin must be one exact loopback HTTP origin")
	}
	listener, err := net.Listen("tcp", development.ListenAddress)
	if err != nil {
		return fmt.Errorf("bind local development listener: %w", err)
	}
	defer func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			runErr = errors.Join(runErr, closeErr)
		}
	}()
	actualPort := listener.Addr().(*net.TCPAddr).Port
	publicOrigin := "http://" + net.JoinHostPort(listenHost, strconv.Itoa(actualPort))
	logger := development.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	f := &fixture{
		databaseURL:   development.DatabaseURL,
		publicOrigin:  publicOrigin,
		browserOrigin: development.BrowserOrigin,
		nowFunction:   time.Now,
	}
	defer func() { runErr = errors.Join(runErr, f.cleanup()) }()
	if err := f.connect(parent); err != nil {
		return errors.New("local development database connectivity failed")
	}
	if err := f.isolateAndMigrate(parent); err != nil {
		return errors.New("local development isolated migration failed")
	}
	if err := f.seedTenant(parent); err != nil {
		return errors.New("local development tenant bootstrap failed")
	}
	consolePassword, err := newDevelopmentPassword()
	if err != nil {
		return errors.New("local development console credential generation failed")
	}
	if err := f.seedDevelopmentPassword(parent, consolePassword); err != nil {
		return errors.New("local development console bootstrap failed")
	}
	if err := f.prepareCryptography(); err != nil {
		return errors.New("local development cryptography bootstrap failed")
	}
	if err := f.startMockServices(); err != nil {
		return errors.New("local development mock services failed")
	}
	if err := f.seedVerificationSecrets(parent); err != nil {
		return errors.New("local development secret bootstrap failed")
	}
	if err := f.activateConfiguration(parent); err != nil {
		return errors.New("local development configuration activation failed")
	}
	if err := f.composeRuntime(parent); err != nil {
		return errors.New("local development runtime composition failed")
	}
	httpServer, registry, err := f.composeDevelopmentServer(logger)
	if err != nil {
		return err
	}
	defer func() {
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		runErr = errors.Join(runErr, registry.Shutdown(shutdownContext))
	}()
	info := DevelopmentInfo{
		GatewayURL: publicOrigin, ApplicationID: f.tenant.applicationID,
		Environment: "development", Feature: developmentFeature, Model: developmentModel,
		BrowserOrigin:          development.BrowserOrigin,
		IdentityTokenURL:       publicOrigin + "/development/v1/identity-token",
		AttestationEvidenceURL: publicOrigin + "/development/v1/attestation-evidence",
		ConsoleURL:             publicOrigin, ConsoleEmail: developmentConsoleEmail,
		ConsolePassword:     consolePassword,
		IOSBundleIdentifier: "dev.latchway.quickstart.ios", AndroidPackageName: "dev.latchway.quickstart.android",
		ReactNativeBundleID: "dev.latchway", ReactNativePackageName: "dev.latchway.reactnative",
	}
	if development.OnReady != nil {
		if err := development.OnReady(info); err != nil {
			return errors.New("local development ready output failed")
		}
	}
	return httpServer.RunListener(parent, 10*time.Second, listener)
}

func validateDevelopmentListenAddress(value string) (string, int, error) {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || portText == "" {
		return "", 0, errors.New("local development listen address must be one exact loopback IP and numeric port")
	}
	address := net.ParseIP(host)
	if address == nil || !address.IsLoopback() || address.String() != host {
		return "", 0, errors.New("local development listen address must use one canonical loopback IP")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 || strconv.Itoa(port) != portText {
		return "", 0, errors.New("local development listen address must use a numeric port between 0 and 65535")
	}
	return host, port, nil
}

func newDevelopmentPassword() (string, error) {
	entropy := make([]byte, 24)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}
	password := "local-" + base64.RawURLEncoding.EncodeToString(entropy)
	clear(entropy)
	return password, nil
}

func (f *fixture) seedDevelopmentPassword(ctx context.Context, password string) error {
	hasher := adminauth.NewDefaultPasswordHasher()
	plaintext := []byte(password)
	hash, err := hasher.Hash(plaintext)
	clear(plaintext)
	if err != nil {
		return err
	}
	_, err = f.pool.Exec(ctx, `
		INSERT INTO admin_password_credentials (
			admin_user_id, password_hash, created_at, changed_at
		) VALUES ($1, $2, $3, $3)
	`, f.tenant.adminUserID, hash.Encoded(), f.clock())
	return err
}

func (f *fixture) composeDevelopmentServer(logger *slog.Logger) (*server.Server, *telemetry.Registry, error) {
	manager, err := secrets.NewManager(secrets.ManagerConfig{Pool: f.pool, Provider: f.envelope})
	if err != nil {
		return nil, nil, errors.New("local development administrative secret manager failed")
	}
	adminAPI, err := adminapi.New(
		f.pool, f.origin(), 12*time.Hour, logger, manager,
		adminapi.WithConfigurationStore(f.configurationStore),
	)
	if err != nil {
		return nil, nil, errors.New("local development Admin API composition failed")
	}
	registry, err := telemetry.NewRegistry(nil)
	if err != nil {
		return nil, nil, errors.New("local development telemetry composition failed")
	}
	keepRegistry := false
	defer func() {
		if !keepRegistry {
			_ = registry.Shutdown(context.Background())
		}
	}()
	developmentHandler, err := f.developmentHandler()
	if err != nil {
		return nil, nil, errors.New("local development helper composition failed")
	}
	cfg := config.Config{
		ListenAddress: f.origin()[len("http://"):], PublicOrigin: f.origin(), Role: config.RoleAll,
		ReadTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second,
	}
	httpServer, err := server.New(cfg, f.pool, logger, server.Handlers{
		AdminAPI: adminAPI.Handler(), ClientAPI: f.clientRuntimeHandler,
		DataPlane: f.dataRuntimeHandler, DevelopmentAPI: developmentHandler,
		Metrics: registry,
		Readiness: server.ReadinessChecks{
			MasterKey: func(checkContext context.Context) error {
				return secrets.CheckMasterKeyConsistency(checkContext, f.pool, f.envelope)
			},
			SigningKey:      func(context.Context) error { return nil },
			WorkerHeartbeat: func(context.Context) error { return nil },
		},
	})
	if err != nil {
		return nil, nil, errors.New("local development HTTP server composition failed")
	}
	keepRegistry = true
	return httpServer, registry, nil
}

type developmentEvidenceRequest struct {
	ChallengeID   string `json:"challenge_id"`
	BindingHash   string `json:"binding_hash"`
	ApplicationID string `json:"application_id"`
	Environment   string `json:"environment"`
	DPoPJKT       string `json:"dpop_jkt"`
	Platform      string `json:"platform"`
}

func (f *fixture) developmentHandler() (http.Handler, error) {
	if f == nil || f.pool == nil || f.oidc == nil || len(f.debugKey) != ed25519.PrivateKeySize ||
		!weborigin.LoopbackHTTP(f.browserOrigin) {
		return nil, errors.New("development helper dependencies are invalid")
	}
	return http.HandlerFunc(f.serveDevelopment), nil
}

func (f *fixture) serveDevelopment(writer http.ResponseWriter, request *http.Request) {
	if request.URL == nil || request.URL.RawPath != "" || request.URL.RawQuery != "" || request.URL.ForceQuery {
		http.NotFound(writer, request)
		return
	}
	switch request.URL.Path {
	case "/development/v1/identity-token":
		f.developmentIdentityToken(writer, request)
	case "/development/v1/attestation-evidence":
		f.developmentEvidence(writer, request)
	default:
		http.NotFound(writer, request)
	}
}

func (f *fixture) developmentIdentityToken(writer http.ResponseWriter, request *http.Request) {
	if !f.developmentRequestAllowed(writer, request, http.MethodGet, "") {
		return
	}
	token, err := f.oidc.token(f.clock())
	if err != nil {
		writeDevelopmentProblem(writer, http.StatusServiceUnavailable, "development_identity_unavailable")
		return
	}
	writeDevelopmentJSON(writer, http.StatusOK, map[string]string{"identity_token": token})
}

func (f *fixture) developmentEvidence(writer http.ResponseWriter, request *http.Request) {
	if !f.developmentRequestAllowed(writer, request, http.MethodPost, "content-type") {
		return
	}
	contentTypes := request.Header.Values("Content-Type")
	if len(contentTypes) != 1 || !strings.EqualFold(contentTypes[0], "application/json") {
		writeDevelopmentProblem(writer, http.StatusBadRequest, "development_evidence_request_invalid")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 8<<10)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	var input developmentEvidenceRequest
	if err := decoder.Decode(&input); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		input.ApplicationID != f.tenant.applicationID || input.Environment != "development" ||
		id.Validate(input.ChallengeID, id.SessionChallenge) != nil ||
		!developmentPlatform(input.Platform) {
		writeDevelopmentProblem(writer, http.StatusBadRequest, "development_evidence_request_invalid")
		return
	}
	dpopThumbprint, err := base64.RawURLEncoding.Strict().DecodeString(input.DPoPJKT)
	if err != nil || len(dpopThumbprint) != sha256.Size ||
		base64.RawURLEncoding.EncodeToString(dpopThumbprint) != input.DPoPJKT {
		writeDevelopmentProblem(writer, http.StatusBadRequest, "development_evidence_request_invalid")
		return
	}
	providedHash, err := base64.RawURLEncoding.Strict().DecodeString(input.BindingHash)
	if err != nil || len(providedHash) != sha256.Size ||
		base64.RawURLEncoding.EncodeToString(providedHash) != input.BindingHash {
		writeDevelopmentProblem(writer, http.StatusBadRequest, "development_evidence_request_invalid")
		return
	}
	var storedHash []byte
	err = f.pool.QueryRow(request.Context(), `
		SELECT challenge.binding_hash
		FROM session_challenges AS challenge
		WHERE challenge.session_challenge_id = $1
		  AND challenge.application_id = $2
		  AND challenge.environment_id = $3
		  AND challenge.dpop_jkt = $4
		  AND challenge.platform = $5
		  AND challenge.attestation_provider = 'debug'
		  AND challenge.attestation_mode = 'required'
		  AND challenge.identity_expires_at > clock_timestamp()
		  AND challenge.expires_at > clock_timestamp()
		  AND EXISTS (
		      SELECT 1
		      FROM organizations AS organization
		      JOIN applications AS application
		        ON application.organization_id = organization.organization_id
		      JOIN environments AS environment
		        ON environment.organization_id = application.organization_id
		       AND environment.application_id = application.application_id
		      JOIN application_users AS application_user
		        ON application_user.organization_id = application.organization_id
		       AND application_user.application_id = application.application_id
		      WHERE organization.organization_id = challenge.organization_id
		        AND application.application_id = challenge.application_id
		        AND environment.environment_id = challenge.environment_id
		        AND application_user.application_user_id = challenge.application_user_id
		        AND organization.status = 'active'
		        AND application.status = 'active'
		        AND environment.status = 'active'
		        AND application_user.status = 'active'
		  )
		  AND EXISTS (
		      SELECT 1
		      FROM active_config_revisions AS active_revision
		      WHERE active_revision.organization_id = challenge.organization_id
		        AND active_revision.application_id = challenge.application_id
		        AND active_revision.environment_id = challenge.environment_id
		        AND active_revision.config_revision_id = challenge.config_revision_id
		  )
		  AND NOT EXISTS (
		      SELECT 1 FROM session_challenge_consumptions AS consumption
		      WHERE consumption.session_challenge_id = challenge.session_challenge_id
		  )
	`, input.ChallengeID, f.tenant.applicationID, f.tenant.environmentID, input.DPoPJKT, input.Platform).Scan(&storedHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeDevelopmentProblem(writer, http.StatusForbidden, "development_evidence_not_authorized")
			return
		}
		writeDevelopmentProblem(writer, http.StatusServiceUnavailable, "development_evidence_unavailable")
		return
	}
	if len(storedHash) != sha256.Size || subtle.ConstantTimeCompare(storedHash, providedHash) != 1 {
		writeDevelopmentProblem(writer, http.StatusForbidden, "development_evidence_not_authorized")
		return
	}
	var bindingHash [sha256.Size]byte
	copy(bindingHash[:], storedHash)
	expiresAt := f.clock().Add(5 * time.Minute).Truncate(time.Second).Unix()
	signature := ed25519.Sign(f.debugKey, attestation.DebugSigningMessage(bindingHash, expiresAt))
	writeDevelopmentJSON(writer, http.StatusOK, map[string]any{
		"key_id": debugKeyID, "binding_hash": input.BindingHash, "expires_at": expiresAt,
		"signature": base64.RawURLEncoding.EncodeToString(signature),
	})
}

func (f *fixture) developmentRequestAllowed(writer http.ResponseWriter, request *http.Request, method, headers string) bool {
	writer.Header().Set("Cache-Control", "no-store")
	origin, originErr := weborigin.Read(request.Header)
	if originErr != nil {
		writeDevelopmentProblem(writer, http.StatusForbidden, "development_origin_not_allowed")
		return false
	}
	if origin != "" {
		if origin != f.browserOrigin {
			writeDevelopmentProblem(writer, http.StatusForbidden, "development_origin_not_allowed")
			return false
		}
		weborigin.SetResponseHeaders(writer.Header(), origin)
	}
	if request.Method == http.MethodOptions {
		requestedMethod, methodErr := weborigin.RequestedMethod(request.Header)
		requestedHeaders, headersErr := weborigin.RequestedHeaders(request.Header)
		if origin == "" || methodErr != nil || requestedMethod != method || headersErr != nil ||
			(headers == "" && len(requestedHeaders) != 0) ||
			(headers != "" && (len(requestedHeaders) != 1 || requestedHeaders[0] != headers)) {
			writeDevelopmentProblem(writer, http.StatusBadRequest, "development_preflight_invalid")
			return false
		}
		weborigin.AppendVary(writer.Header(), "Access-Control-Request-Method")
		weborigin.AppendVary(writer.Header(), "Access-Control-Request-Headers")
		writer.Header().Set("Access-Control-Allow-Methods", method)
		if headers != "" {
			writer.Header().Set("Access-Control-Allow-Headers", headers)
		}
		writer.WriteHeader(http.StatusNoContent)
		return false
	}
	if request.Method != method {
		writer.Header().Set("Allow", method+", "+http.MethodOptions)
		writeDevelopmentProblem(writer, http.StatusMethodNotAllowed, "development_method_not_allowed")
		return false
	}
	return true
}

func developmentPlatform(platform string) bool {
	switch platform {
	case "ios", "android", "web", "react_native_ios", "react_native_android":
		return true
	default:
		return false
	}
}

func writeDevelopmentProblem(writer http.ResponseWriter, status int, code string) {
	writeDevelopmentJSON(writer, status, map[string]string{"code": code})
}

func writeDevelopmentJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
