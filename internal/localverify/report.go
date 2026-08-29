// Package localverify runs the destructive Latchway local conformance vertical
// inside a short-lived PostgreSQL schema and returns redaction-safe evidence.
package localverify

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
)

const ReportVersion = 1

type Check struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

type Report struct {
	Version int     `json:"version"`
	Kind    string  `json:"kind"`
	State   string  `json:"state"`
	Checks  []Check `json:"checks"`
	cause   error
}

func newReport() Report {
	return Report{Version: ReportVersion, Kind: "local", State: "passed", Checks: make([]Check, 0, 20)}
}

func (report *Report) add(name, state, detail string) {
	report.Checks = append(report.Checks, Check{Name: name, State: state, Detail: detail})
	if state == "failed" {
		report.State = "failed"
	}
}

func (report Report) Error() error {
	if report.State == "passed" {
		return nil
	}
	if report.cause != nil {
		return fmt.Errorf("local verification failed; inspect the emitted redaction-safe report: %w", report.cause)
	}
	return errors.New("local verification failed; inspect the emitted redaction-safe report")
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
	Name      string        `xml:"name,attr"`
	ClassName string        `xml:"classname,attr"`
	Failure   *junitFailure `xml:"failure,omitempty"`
	Skipped   *junitSkipped `xml:"skipped,omitempty"`
}

type junitFailure struct {
	Message string `xml:"message,attr"`
	Detail  string `xml:",chardata"`
}

type junitSkipped struct {
	Message string `xml:"message,attr"`
}

// MarshalJUnit returns stable evidence: check ordering is the execution
// ordering, and volatile timestamps, durations, resource IDs, and database
// coordinates are intentionally absent.
func (report Report) MarshalJUnit() ([]byte, error) {
	suite := junitSuite{
		Name: "latchway.verify.local", Tests: len(report.Checks),
		Cases: make([]junitCase, 0, len(report.Checks)),
	}
	for _, check := range report.Checks {
		item := junitCase{Name: check.Name, ClassName: "latchway.verify.local"}
		switch check.State {
		case "passed":
		case "failed":
			suite.Failures++
			item.Failure = &junitFailure{Message: "verification failed", Detail: check.Detail}
		case "skipped":
			suite.Skipped++
			item.Skipped = &junitSkipped{Message: check.Detail}
		default:
			return nil, errors.New("local verification report contains an invalid check state")
		}
		suite.Cases = append(suite.Cases, item)
	}
	var output bytes.Buffer
	output.WriteString(xml.Header)
	encoder := xml.NewEncoder(&output)
	encoder.Indent("", "  ")
	if err := encoder.Encode(suite); err != nil {
		return nil, err
	}
	output.WriteByte('\n')
	return output.Bytes(), nil
}
