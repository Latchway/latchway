package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type config struct {
	SchemaVersion int              `json:"schema_version"`
	Environment   environment      `json:"environment"`
	Gateway       gatewayConfig    `json:"gateway"`
	Session       sessionConfig    `json:"session"`
	NonStream     requestConfig    `json:"non_stream_request"`
	Stream        requestConfig    `json:"stream_request"`
	Baseline      baselineConfig   `json:"direct_upstream_baseline"`
	Quota         quotaConfig      `json:"quota"`
	Targets       targetConfig     `json:"targets"`
	Metadata      evidenceMetadata `json:"metadata"`
}

type environment struct {
	Label               string `json:"label"`
	CPU                 string `json:"cpu"`
	Memory              string `json:"memory"`
	PostgreSQL          string `json:"postgresql"`
	BodyLoggingDisabled bool   `json:"body_logging_disabled"`
	WarmConfigCache     bool   `json:"warm_configuration_cache"`
}

type evidenceMetadata struct {
	LocalDockerImageID  string `json:"local_docker_image_id,omitempty"`
	ReleaseOCIReference string `json:"release_oci_reference,omitempty"`
	Deployment          string `json:"deployment"`
	Operator            string `json:"operator"`
}

type gatewayConfig struct {
	BaseURL             string `json:"base_url"`
	ReadyPath           string `json:"ready_path"`
	PID                 int    `json:"pid,omitempty"`
	PIDFile             string `json:"pid_file,omitempty"`
	ProcessNameContains string `json:"process_name_contains"`
}

type sessionConfig struct {
	AccessTokenEnv string `json:"access_token_env"`
	PrivateJWKEnv  string `json:"private_jwk_file_env"`
}

type requestConfig struct {
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Headers        map[string]string `json:"headers"`
	Body           json.RawMessage   `json:"body"`
	ExpectedStatus int               `json:"expected_status"`
}

type baselineConfig struct {
	URL            string            `json:"url"`
	Headers        map[string]string `json:"headers,omitempty"`
	Body           json.RawMessage   `json:"body,omitempty"`
	ExpectedStatus int               `json:"expected_status"`
}

type quotaConfig struct {
	NonStreamSnapshotPath  string        `json:"non_stream_snapshot_path"`
	StreamSnapshotPath     string        `json:"stream_snapshot_path"`
	ContentionSnapshotPath string        `json:"contention_snapshot_path"`
	ContentionRequest      requestConfig `json:"contention_request"`
	ContentionMetric       string        `json:"contention_metric"`
	ContentionAttempts     int           `json:"contention_attempts"`
	DenialStatus           int           `json:"denial_status"`
}

type targetConfig struct {
	OverheadSamples                int     `json:"overhead_samples"`
	OverheadWarmup                 int     `json:"overhead_warmup"`
	P50Milliseconds                float64 `json:"p50_gateway_overhead_ms"`
	P95Milliseconds                float64 `json:"p95_gateway_overhead_ms"`
	P99Milliseconds                float64 `json:"p99_gateway_overhead_ms"`
	NonStreamRPS                   int     `json:"non_stream_rps"`
	NonStreamDurationSeconds       int     `json:"non_stream_duration_seconds"`
	MaximumScheduleLagMilliseconds int     `json:"maximum_schedule_lag_ms"`
	SSEConcurrency                 int     `json:"sse_concurrency"`
	SSEHoldSeconds                 int     `json:"sse_hold_seconds"`
	MaximumStreamGrowthMiB         float64 `json:"maximum_stream_memory_growth_mib"`
	MaximumStreamSlopeMiBPerMinute float64 `json:"maximum_stream_memory_slope_mib_per_minute"`
	IdleWarmupSeconds              int     `json:"idle_warmup_seconds"`
	IdleMemoryMiB                  float64 `json:"idle_memory_mib"`
	RequestTimeoutSeconds          int     `json:"request_timeout_seconds"`
}

func loadConfig(path string) (config, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return config{}, fmt.Errorf("read config: %w", err)
	}
	cfg, err := decodeConfig(contents)
	if err != nil {
		return config{}, err
	}
	if err := cfg.validate(filepath.Dir(path)); err != nil {
		return config{}, err
	}
	return cfg, nil
}

func decodeConfig(contents []byte) (config, error) {
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var cfg config
	if err := decoder.Decode(&cfg); err != nil {
		return config{}, fmt.Errorf("decode config: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return config{}, errors.New("decode config: trailing JSON value")
	}
	return cfg, nil
}

func (cfg *config) validate(baseDir string) error {
	if cfg.SchemaVersion != 1 {
		return fmt.Errorf("schema_version must be 1, got %d", cfg.SchemaVersion)
	}
	if cfg.Environment.Label == "" || cfg.Environment.CPU == "" || cfg.Environment.Memory == "" || cfg.Environment.PostgreSQL == "" {
		return errors.New("environment label, cpu, memory, and postgresql are required")
	}
	for name, value := range map[string]string{
		"environment.label": cfg.Environment.Label, "environment.cpu": cfg.Environment.CPU,
		"environment.memory": cfg.Environment.Memory, "environment.postgresql": cfg.Environment.PostgreSQL,
	} {
		if placeholder(value) {
			return fmt.Errorf("%s still contains a placeholder", name)
		}
	}
	if !cfg.Environment.BodyLoggingDisabled || !cfg.Environment.WarmConfigCache {
		return errors.New("release load evidence requires body logging disabled and a warm configuration cache")
	}
	base, err := url.Parse(cfg.Gateway.BaseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return errors.New("gateway.base_url must be one absolute URL without query or fragment")
	}
	if cfg.Gateway.ReadyPath == "" {
		cfg.Gateway.ReadyPath = "/readyz"
	}
	if err := validatePath(cfg.Gateway.ReadyPath, "gateway.ready_path"); err != nil {
		return err
	}
	if cfg.Gateway.PID <= 0 && cfg.Gateway.PIDFile == "" {
		return errors.New("gateway.pid or gateway.pid_file is required for memory gates")
	}
	if cfg.Gateway.ProcessNameContains == "" || len(cfg.Gateway.ProcessNameContains) > 64 || strings.ContainsAny(cfg.Gateway.ProcessNameContains, "\r\n\x00/\\") {
		return errors.New("gateway.process_name_contains must be one bounded executable-name fragment")
	}
	if cfg.Gateway.PIDFile != "" && !filepath.IsAbs(cfg.Gateway.PIDFile) {
		cfg.Gateway.PIDFile = filepath.Join(baseDir, cfg.Gateway.PIDFile)
	}
	if !validEnvironmentName(cfg.Session.AccessTokenEnv) || !validEnvironmentName(cfg.Session.PrivateJWKEnv) {
		return errors.New("session environment-variable names must contain only ASCII letters, digits, and underscores")
	}
	cfg.NonStream.Method = strings.ToUpper(cfg.NonStream.Method)
	if err := cfg.NonStream.validate("non_stream_request"); err != nil {
		return err
	}
	cfg.Stream.Method = strings.ToUpper(cfg.Stream.Method)
	if err := cfg.Stream.validate("stream_request"); err != nil {
		return err
	}
	baselineURL, err := url.Parse(cfg.Baseline.URL)
	if err != nil || (baselineURL.Scheme != "http" && baselineURL.Scheme != "https") || baselineURL.Host == "" || baselineURL.User != nil || baselineURL.RawQuery != "" || baselineURL.Fragment != "" {
		return errors.New("direct_upstream_baseline.url must be absolute")
	}
	if len(cfg.Baseline.Body) == 0 {
		cfg.Baseline.Body = append(json.RawMessage(nil), cfg.NonStream.Body...)
	}
	if cfg.Baseline.ExpectedStatus < 100 || cfg.Baseline.ExpectedStatus > 599 {
		return errors.New("direct_upstream_baseline.expected_status must be an HTTP status")
	}
	for field, value := range map[string]string{
		"quota.non_stream_snapshot_path": cfg.Quota.NonStreamSnapshotPath,
		"quota.stream_snapshot_path":     cfg.Quota.StreamSnapshotPath,
		"quota.contention_snapshot_path": cfg.Quota.ContentionSnapshotPath,
	} {
		if err := validatePath(value, field); err != nil {
			return err
		}
	}
	cfg.Quota.ContentionRequest.Method = strings.ToUpper(cfg.Quota.ContentionRequest.Method)
	if err := cfg.Quota.ContentionRequest.validate("quota.contention_request"); err != nil {
		return err
	}
	if cfg.Quota.ContentionMetric == "" || cfg.Quota.ContentionAttempts < 2 {
		return errors.New("quota contention_metric and at least two contention_attempts are required")
	}
	if cfg.Quota.DenialStatus == 0 {
		cfg.Quota.DenialStatus = 429
	}
	if cfg.Targets.OverheadSamples < 20 || cfg.Targets.OverheadWarmup < 1 ||
		cfg.Targets.P50Milliseconds <= 0 || cfg.Targets.P95Milliseconds <= 0 || cfg.Targets.P99Milliseconds <= 0 ||
		cfg.Targets.P50Milliseconds > cfg.Targets.P95Milliseconds || cfg.Targets.P95Milliseconds > cfg.Targets.P99Milliseconds {
		return errors.New("overhead targets require ordered positive p50/p95/p99 thresholds, at least 20 samples, and warmup")
	}
	if cfg.Targets.NonStreamRPS < 100 || cfg.Targets.NonStreamDurationSeconds < 10 || cfg.Targets.MaximumScheduleLagMilliseconds <= 0 {
		return errors.New("non-stream target must run at least 100 RPS for 10 seconds with an explicit schedule-lag bound")
	}
	if cfg.Targets.SSEConcurrency < 500 || cfg.Targets.SSEHoldSeconds < 10 ||
		cfg.Targets.MaximumStreamGrowthMiB <= 0 || cfg.Targets.MaximumStreamSlopeMiBPerMinute <= 0 {
		return errors.New("SSE target requires at least 500 streams held for 10 seconds and explicit positive memory growth/slope bounds")
	}
	if cfg.Targets.IdleWarmupSeconds < 1 || cfg.Targets.IdleMemoryMiB <= 0 || cfg.Targets.IdleMemoryMiB > 256 {
		return errors.New("idle target requires a positive warmup and a memory ceiling no greater than 256 MiB")
	}
	if cfg.Targets.RequestTimeoutSeconds < 1 {
		return errors.New("request_timeout_seconds must be positive")
	}
	for key, value := range map[string]string{
		"deployment": cfg.Metadata.Deployment,
		"operator":   cfg.Metadata.Operator,
	} {
		if placeholder(value) {
			return fmt.Errorf("metadata.%s is required and cannot be a placeholder", key)
		}
	}
	if err := cfg.Metadata.validateImageEvidence(); err != nil {
		return err
	}
	return nil
}

func (metadata evidenceMetadata) validateImageEvidence() error {
	if metadata.LocalDockerImageID != "" && metadata.ReleaseOCIReference != "" {
		return errors.New("metadata must contain exactly one of local_docker_image_id or release_oci_reference")
	}
	if metadata.LocalDockerImageID != "" {
		if placeholder(metadata.LocalDockerImageID) || !validLocalDockerImageID(metadata.LocalDockerImageID) {
			return errors.New("metadata.local_docker_image_id must be one lowercase sha256 Docker image ID")
		}
		return nil
	}
	if metadata.ReleaseOCIReference != "" {
		if placeholder(metadata.ReleaseOCIReference) || !validReleaseOCIReference(metadata.ReleaseOCIReference) {
			return errors.New("metadata.release_oci_reference must be one fully qualified registry repository pinned by lowercase sha256 digest")
		}
		return nil
	}
	return errors.New("metadata must contain exactly one of local_docker_image_id or release_oci_reference")
}

func (request requestConfig) validate(name string) error {
	if request.Method == "" {
		return fmt.Errorf("%s.method is required", name)
	}
	request.Method = strings.ToUpper(request.Method)
	if err := validatePath(request.Path, name+".path"); err != nil {
		return err
	}
	if request.ExpectedStatus < 100 || request.ExpectedStatus > 599 {
		return fmt.Errorf("%s.expected_status must be an HTTP status", name)
	}
	if !json.Valid(request.Body) {
		return fmt.Errorf("%s.body must be valid JSON", name)
	}
	for key, value := range request.Headers {
		if strings.TrimSpace(key) == "" || strings.ContainsAny(key+value, "\r\n\x00") {
			return fmt.Errorf("%s contains an unsafe header", name)
		}
		if strings.EqualFold(key, "Authorization") || strings.EqualFold(key, "DPoP") {
			return fmt.Errorf("%s must not embed session credentials", name)
		}
	}
	return nil
}

func validatePath(path, field string) error {
	parsed, err := url.Parse(path)
	if err != nil || !strings.HasPrefix(path, "/") || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("%s must be one absolute-path reference without query or fragment", field)
	}
	return nil
}

func validEnvironmentName(value string) bool {
	if value == "" {
		return false
	}
	for index, character := range value {
		if !((character >= 'A' && character <= 'Z') || (character >= 'a' && character <= 'z') || character == '_' || (index > 0 && character >= '0' && character <= '9')) {
			return false
		}
	}
	return true
}

func (cfg config) timeout() time.Duration {
	return time.Duration(cfg.Targets.RequestTimeoutSeconds) * time.Second
}

func placeholder(value string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(value))
	return trimmed == "" || strings.Contains(trimmed, "replace") || strings.ContainsAny(trimmed, "<>")
}

func validLocalDockerImageID(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
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
	name, digest, found := strings.Cut(value, "@sha256:")
	if !found || name == "" || len(name) > 255 || len(digest) != 64 || strings.ToLower(value) != value {
		return false
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return false
	}
	registry, repository, found := strings.Cut(name, "/")
	if !found || !validRegistryName(registry) || repository == "" {
		return false
	}
	for _, component := range strings.Split(repository, "/") {
		if !validRepositoryComponent(component) {
			return false
		}
	}
	return true
}

func validRegistryName(value string) bool {
	host := value
	if strings.Count(value, ":") > 1 {
		return false
	}
	if parsedHost, port, found := strings.Cut(value, ":"); found {
		if parsedHost == "" || port == "" || len(port) > 5 {
			return false
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return false
		}
		host = parsedHost
	}
	if !strings.Contains(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" || len(label) > 63 || !asciiLowerAlphaNumeric(label[0]) || !asciiLowerAlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !asciiLowerAlphaNumeric(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func validRepositoryComponent(value string) bool {
	if value == "" || !asciiLowerAlphaNumeric(value[0]) || !asciiLowerAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		character := value[index]
		if !asciiLowerAlphaNumeric(character) && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}

func asciiLowerAlphaNumeric(character byte) bool {
	return (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9')
}

func validCommitHash(value string) bool {
	if (len(value) != 40 && len(value) != 64) || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
