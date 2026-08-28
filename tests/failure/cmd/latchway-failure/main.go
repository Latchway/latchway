package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

type matrix struct {
	SchemaVersion int        `json:"schema_version"`
	Scenarios     []scenario `json:"scenarios"`
}

type scenario struct {
	ID                  string       `json:"id"`
	Requirement         string       `json:"requirement"`
	Kind                string       `json:"kind"`
	RequiresEnvironment []string     `json:"requires_environment,omitempty"`
	Invocations         []invocation `json:"invocations,omitempty"`
	EvidenceNotes       string       `json:"evidence_notes,omitempty"`
}

type invocation struct {
	Package string `json:"package"`
	Run     string `json:"run"`
	Race    bool   `json:"race"`
}

type evidenceReport struct {
	SchemaVersion   int              `json:"schema_version"`
	Kind            string           `json:"kind"`
	Scope           string           `json:"scope"`
	Commit          string           `json:"commit"`
	WorktreeClean   bool             `json:"worktree_clean"`
	StartedAt       time.Time        `json:"started_at"`
	FinishedAt      time.Time        `json:"finished_at"`
	Results         []scenarioResult `json:"results"`
	AutomatedPassed bool             `json:"automated_passed"`
	ReleasePassed   bool             `json:"release_passed"`
}

type scenarioResult struct {
	ID          string             `json:"id"`
	Requirement string             `json:"requirement"`
	Kind        string             `json:"kind"`
	Status      string             `json:"status"`
	DurationMS  int64              `json:"duration_ms"`
	Error       string             `json:"error,omitempty"`
	Logs        []invocationResult `json:"logs,omitempty"`
	Evidence    string             `json:"evidence,omitempty"`
	Notes       string             `json:"notes,omitempty"`
}

type invocationResult struct {
	Package  string `json:"package"`
	Run      string `json:"run"`
	Race     bool   `json:"race"`
	Log      string `json:"log"`
	SHA256   string `json:"sha256"`
	ExitCode int    `json:"exit_code"`
}

type externalEvidence struct {
	SchemaVersion int                 `json:"schema_version"`
	ScenarioID    string              `json:"scenario_id"`
	Status        string              `json:"status"`
	Commit        string              `json:"commit"`
	StartedAt     time.Time           `json:"started_at"`
	FinishedAt    time.Time           `json:"finished_at"`
	Environment   map[string]string   `json:"environment"`
	Assertions    []externalAssertion `json:"assertions"`
	Artifacts     []externalArtifact  `json:"artifacts"`
}

type externalAssertion struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type externalArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func main() {
	var matrixPath, outputPath, scope, externalDir string
	var timeout time.Duration
	flag.StringVar(&matrixPath, "matrix", "tests/failure/matrix.json", "failure matrix JSON")
	flag.StringVar(&outputPath, "output", "", "required JSON evidence output")
	flag.StringVar(&scope, "scope", "automated", "automated or release")
	flag.StringVar(&externalDir, "external-evidence-dir", "", "directory containing signed-off external scenario JSON and artifacts")
	flag.DurationVar(&timeout, "test-timeout", 10*time.Minute, "timeout for each fixed go test invocation")
	flag.Parse()
	if outputPath == "" || (scope != "automated" && scope != "release") || timeout <= 0 || timeout > 30*time.Minute {
		fmt.Fprintln(os.Stderr, "-output, a valid -scope, and a bounded -test-timeout are required")
		os.Exit(2)
	}
	matrixValue, err := loadMatrix(matrixPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	commit := currentCommit()
	if commit == "" {
		fmt.Fprintln(os.Stderr, "cannot resolve current git commit")
		os.Exit(2)
	}
	clean, err := worktreeClean()
	if err != nil || (scope == "release" && !clean) {
		fmt.Fprintf(os.Stderr, "release failure evidence requires a clean worktree: clean=%t error=%v\n", clean, err)
		os.Exit(2)
	}
	started := time.Now().UTC()
	result := evidenceReport{SchemaVersion: 1, Kind: "latchway_failure_evidence", Scope: scope, Commit: commit, WorktreeClean: clean, StartedAt: started}
	logDirectory := strings.TrimSuffix(outputPath, filepath.Ext(outputPath)) + ".logs"
	if err := os.MkdirAll(logDirectory, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	for _, scenario := range matrixValue.Scenarios {
		if scenario.Kind == "automated" {
			result.Results = append(result.Results, runAutomated(scenario, logDirectory, timeout))
		} else {
			result.Results = append(result.Results, validateExternal(scenario, externalDir, commit, scope))
		}
	}
	result.FinishedAt = time.Now().UTC()
	result.AutomatedPassed = true
	result.ReleasePassed = true
	for _, scenario := range result.Results {
		if scenario.Kind == "automated" && scenario.Status != "passed" {
			result.AutomatedPassed = false
		}
		if scenario.Status != "passed" {
			result.ReleasePassed = false
		}
	}
	if err := writeEvidence(outputPath, result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if (scope == "automated" && !result.AutomatedPassed) || (scope == "release" && !result.ReleasePassed) {
		os.Exit(1)
	}
}

func loadMatrix(path string) (matrix, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return matrix{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var value matrix
	if err := decoder.Decode(&value); err != nil {
		return matrix{}, fmt.Errorf("decode matrix: %w", err)
	}
	if err := requireEOF(decoder); err != nil {
		return matrix{}, err
	}
	if value.SchemaVersion != 1 || len(value.Scenarios) == 0 {
		return matrix{}, errors.New("matrix schema_version must be 1 and scenarios cannot be empty")
	}
	seen := make(map[string]bool)
	for _, scenario := range value.Scenarios {
		if scenario.ID == "" || scenario.Requirement == "" || seen[scenario.ID] {
			return matrix{}, errors.New("scenario identifiers and requirements must be nonempty and unique")
		}
		seen[scenario.ID] = true
		switch scenario.Kind {
		case "automated":
			if len(scenario.Invocations) == 0 || scenario.EvidenceNotes != "" {
				return matrix{}, fmt.Errorf("automated scenario %s has invalid invocation/evidence shape", scenario.ID)
			}
			for _, invocation := range scenario.Invocations {
				if !strings.HasPrefix(invocation.Package, "./") || invocation.Run == "" || strings.ContainsAny(invocation.Package+invocation.Run, "\r\n\x00") {
					return matrix{}, fmt.Errorf("automated scenario %s has an unsafe invocation", scenario.ID)
				}
			}
		case "external":
			if len(scenario.Invocations) != 0 || scenario.EvidenceNotes == "" {
				return matrix{}, fmt.Errorf("external scenario %s has invalid evidence shape", scenario.ID)
			}
		default:
			return matrix{}, fmt.Errorf("scenario %s has unknown kind %q", scenario.ID, scenario.Kind)
		}
	}
	return value, nil
}

func runAutomated(scenario scenario, logDirectory string, timeout time.Duration) scenarioResult {
	started := time.Now()
	result := scenarioResult{ID: scenario.ID, Requirement: scenario.Requirement, Kind: scenario.Kind, Status: "passed"}
	for _, name := range scenario.RequiresEnvironment {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			result.Status = "blocked"
			result.Error = "required test environment is unavailable: " + name
			result.DurationMS = time.Since(started).Milliseconds()
			return result
		}
	}
	for index, invocation := range scenario.Invocations {
		args := []string{"test", "-count=1", "-json", "-timeout", timeout.String()}
		if invocation.Race {
			args = append(args, "-race")
		}
		args = append(args, "-run", invocation.Run, invocation.Package)
		ctx, cancel := context.WithTimeout(context.Background(), timeout+30*time.Second)
		command := exec.CommandContext(ctx, "go", args...)
		command.Env = append(os.Environ(), "GOCACHE=/tmp/latchway-go-cache")
		output, commandErr := command.CombinedOutput()
		timedOut := errors.Is(ctx.Err(), context.DeadlineExceeded)
		cancel()
		logName := fmt.Sprintf("%s-%02d.jsonl", scenario.ID, index+1)
		logPath := filepath.Join(logDirectory, logName)
		writeErr := os.WriteFile(logPath, output, 0o644)
		digest := sha256.Sum256(output)
		exitCode := 0
		if commandErr != nil {
			exitCode = 1
			var exitErr *exec.ExitError
			if errors.As(commandErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			}
		}
		result.Logs = append(result.Logs, invocationResult{
			Package: invocation.Package, Run: invocation.Run, Race: invocation.Race,
			Log: logPath, SHA256: hex.EncodeToString(digest[:]), ExitCode: exitCode,
		})
		if writeErr != nil {
			result.Status = "failed"
			result.Error = "write bounded test log: " + writeErr.Error()
			break
		}
		if commandErr != nil {
			result.Status = "failed"
			if timedOut {
				result.Error = "fixed go test invocation timed out"
			} else {
				result.Error = fmt.Sprintf("go test invocation %d failed with exit code %d", index+1, exitCode)
			}
			break
		}
		if !goTestLogProvesPass(output) {
			result.Status = "failed"
			result.Error = fmt.Sprintf("go test invocation %d emitted no passing test event (a skip is not evidence)", index+1)
			break
		}
	}
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}

func goTestLogProvesPass(output []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(output))
	passedTest := false
	for {
		var event struct {
			Action string `json:"Action"`
			Test   string `json:"Test"`
		}
		if err := decoder.Decode(&event); err != nil {
			return errors.Is(err, io.EOF) && passedTest
		}
		if event.Action == "pass" && event.Test != "" {
			passedTest = true
		}
	}
}

func validateExternal(scenario scenario, directory, commit, scope string) scenarioResult {
	started := time.Now()
	result := scenarioResult{
		ID: scenario.ID, Requirement: scenario.Requirement, Kind: scenario.Kind,
		Status: "external_required", Notes: scenario.EvidenceNotes,
	}
	if scope != "release" {
		result.DurationMS = time.Since(started).Milliseconds()
		return result
	}
	if directory == "" {
		result.Status = "failed"
		result.Error = "release scope requires -external-evidence-dir"
		result.DurationMS = time.Since(started).Milliseconds()
		return result
	}
	path := filepath.Join(directory, scenario.ID+".json")
	evidence, err := loadExternal(path)
	if err == nil {
		err = validateExternalDocument(directory, scenario.ID, commit, evidence)
	}
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
	} else {
		result.Status = "passed"
		result.Evidence = path
	}
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}

func loadExternal(path string) (externalEvidence, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return externalEvidence{}, fmt.Errorf("read external evidence: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	var value externalEvidence
	if err := decoder.Decode(&value); err != nil {
		return externalEvidence{}, errors.New("decode external evidence")
	}
	if err := requireEOF(decoder); err != nil {
		return externalEvidence{}, err
	}
	return value, nil
}

func validateExternalDocument(directory, scenarioID, commit string, evidence externalEvidence) error {
	if evidence.SchemaVersion != 1 || evidence.ScenarioID != scenarioID || evidence.Status != "passed" || evidence.Commit != commit {
		return errors.New("external evidence identity, status, or commit does not match this release candidate")
	}
	if !validCommit(evidence.Commit) || evidence.StartedAt.IsZero() || !evidence.FinishedAt.After(evidence.StartedAt) ||
		evidence.FinishedAt.Sub(evidence.StartedAt) > 24*time.Hour || evidence.FinishedAt.After(time.Now().UTC().Add(5*time.Minute)) ||
		len(evidence.Environment) == 0 || len(evidence.Assertions) == 0 || len(evidence.Artifacts) == 0 {
		return errors.New("external evidence is missing bounded timestamps, environment, assertions, or artifacts")
	}
	for _, key := range []string{"image_digest", "platform", "postgresql", "operator"} {
		if strings.TrimSpace(evidence.Environment[key]) == "" {
			return fmt.Errorf("external evidence environment is missing %s", key)
		}
	}
	imageParts := strings.Split(evidence.Environment["image_digest"], "@sha256:")
	if len(imageParts) != 2 || imageParts[0] == "" || !validSHA256(imageParts[1]) {
		return errors.New("external evidence must bind an immutable OCI sha256 image digest")
	}
	for _, assertion := range evidence.Assertions {
		if assertion.Name == "" || assertion.Detail == "" || !assertion.Passed {
			return errors.New("external evidence contains a missing or failed assertion")
		}
	}
	for _, artifact := range evidence.Artifacts {
		clean := filepath.Clean(artifact.Path)
		if artifact.Path == "" || filepath.IsAbs(artifact.Path) || clean != artifact.Path || clean == "." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || !validSHA256(artifact.SHA256) {
			return errors.New("external evidence contains an unsafe artifact reference")
		}
		path := filepath.Join(directory, clean)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("read external artifact %s: %w", artifact.Path, err)
		}
		if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > 100<<20 {
			return fmt.Errorf("external artifact %s must be a nonempty regular file no larger than 100 MiB", artifact.Path)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("read external artifact %s: %w", artifact.Path, err)
		}
		hasher := sha256.New()
		_, copyErr := io.Copy(hasher, file)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return fmt.Errorf("hash external artifact %s", artifact.Path)
		}
		if !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), artifact.SHA256) {
			return fmt.Errorf("external artifact %s digest mismatch", artifact.Path)
		}
	}
	return nil
}

func validCommit(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validSHA256(value string) bool {
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func requireEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON document contains trailing data")
	}
	return nil
}

func currentCommit() string {
	output, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func worktreeClean() (bool, error) {
	output, err := exec.Command("git", "status", "--porcelain=v1").Output()
	if err != nil {
		return false, err
	}
	return len(strings.TrimSpace(string(output))) == 0, nil
}

func writeEvidence(path string, result evidenceReport) error {
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return err
	}
	return writeJUnit(path+".junit.xml", result)
}

type junitSuite struct {
	XMLName  xml.Name    `xml:"testsuite"`
	Name     string      `xml:"name,attr"`
	Tests    int         `xml:"tests,attr"`
	Failures int         `xml:"failures,attr"`
	Skipped  int         `xml:"skipped,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name    string        `xml:"name,attr"`
	Time    string        `xml:"time,attr"`
	Failure *junitFailure `xml:"failure,omitempty"`
	Skipped *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

func writeJUnit(path string, result evidenceReport) error {
	suite := junitSuite{Name: "latchway-failure-matrix", Tests: len(result.Results)}
	for _, scenario := range result.Results {
		testCase := junitCase{Name: scenario.ID, Time: fmt.Sprintf("%.3f", float64(scenario.DurationMS)/1000)}
		switch scenario.Status {
		case "passed":
		case "external_required":
			suite.Skipped++
			testCase.Skipped = &junitSkipped{Message: scenario.Notes}
		default:
			suite.Failures++
			testCase.Failure = &junitFailure{Message: scenario.Status, Body: scenario.Error}
		}
		suite.Cases = append(suite.Cases, testCase)
	}
	encoded, err := xml.MarshalIndent(suite, "", "  ")
	if err != nil {
		return err
	}
	encoded = append([]byte(xml.Header), encoded...)
	encoded = append(encoded, '\n')
	return os.WriteFile(path, encoded, 0o644)
}
