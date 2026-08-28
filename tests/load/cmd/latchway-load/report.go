package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type report struct {
	SchemaVersion     int               `json:"schema_version"`
	Kind              string            `json:"kind"`
	StartedAt         time.Time         `json:"started_at"`
	FinishedAt        time.Time         `json:"finished_at"`
	Commit            string            `json:"commit,omitempty"`
	Environment       environment       `json:"environment"`
	QuotaFixture      quotaFixtureFacts `json:"quota_fixture"`
	Metadata          evidenceMetadata  `json:"metadata"`
	ProcessExecutable string            `json:"observed_process_executable"`
	WorktreeClean     bool              `json:"worktree_clean"`
	Gates             []gateResult      `json:"gates"`
	CompleteSuite     bool              `json:"complete_suite"`
	LoadTargetsPassed bool              `json:"load_targets_passed"`
}

type gateResult struct {
	Name       string         `json:"name"`
	Status     string         `json:"status"`
	StartedAt  time.Time      `json:"started_at"`
	DurationMS int64          `json:"duration_ms"`
	Error      string         `json:"error,omitempty"`
	Metrics    map[string]any `json:"metrics,omitempty"`
}

func newGate(name string) gateResult {
	return gateResult{Name: name, Status: "failed", StartedAt: time.Now().UTC()}
}

func (gate *gateResult) finish(err error) {
	gate.DurationMS = time.Since(gate.StartedAt).Milliseconds()
	if err == nil {
		gate.Status = "passed"
		return
	}
	gate.Status = "failed"
	gate.Error = err.Error()
}

func writeReport(path string, result report) error {
	result.FinishedAt = time.Now().UTC()
	result.LoadTargetsPassed = result.CompleteSuite && len(result.Gates) > 0
	for _, gate := range result.Gates {
		if gate.Status != "passed" {
			result.LoadTargetsPassed = false
		}
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if path == "" || path == "-" {
		_, err = os.Stdout.Write(encoded)
		return err
	}
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
	Time     string      `xml:"time,attr"`
	Cases    []junitCase `xml:"testcase"`
}

type junitCase struct {
	Name    string        `xml:"name,attr"`
	Time    string        `xml:"time,attr"`
	Failure *junitFailure `xml:"failure,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

func writeJUnit(path string, result report) error {
	suite := junitSuite{Name: "latchway-load", Tests: len(result.Gates)}
	for _, gate := range result.Gates {
		testCase := junitCase{Name: gate.Name, Time: fmt.Sprintf("%.3f", float64(gate.DurationMS)/1000)}
		if gate.Status != "passed" {
			suite.Failures++
			testCase.Failure = &junitFailure{Message: gate.Status, Body: gate.Error}
		}
		suite.Cases = append(suite.Cases, testCase)
		suite.Time = fmt.Sprintf("%.3f", time.Since(result.StartedAt).Seconds())
	}
	encoded, err := xml.MarshalIndent(suite, "", "  ")
	if err != nil {
		return err
	}
	encoded = append([]byte(xml.Header), encoded...)
	encoded = append(encoded, '\n')
	return os.WriteFile(path, encoded, 0o644)
}
