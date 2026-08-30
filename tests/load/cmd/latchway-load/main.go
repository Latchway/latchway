package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

var allGateNames = []string{"preflight", "idle", "overhead", "nonstream", "streams", "contention"}

func main() {
	var configPath, outputPath, mode string
	var acknowledge bool
	flag.StringVar(&configPath, "config", "", "path to a versioned load-gate JSON config")
	flag.StringVar(&outputPath, "output", "-", "JSON evidence path; JUnit is written beside a file output")
	flag.StringVar(&mode, "mode", "all", "all or a comma-separated subset of preflight,idle,overhead,nonstream,streams,contention")
	flag.BoolVar(&acknowledge, "acknowledge-load", false, "confirm the target is an isolated load-test environment")
	flag.Parse()
	if configPath == "" || !acknowledge {
		fmt.Fprintln(os.Stderr, "-config and -acknowledge-load are required; never point this harness at an unapproved environment")
		os.Exit(2)
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	selected, complete, err := selectedGates(mode)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	client, err := newProtectedClient(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	pid, err := resolvePID(cfg.Gateway)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	executable, err := processExecutable(pid)
	if err != nil || !strings.Contains(strings.ToLower(executable), strings.ToLower(cfg.Gateway.ProcessNameContains)) {
		fmt.Fprintf(os.Stderr, "gateway pid %d executable %q does not match configured process identity: %v\n", pid, executable, err)
		os.Exit(2)
	}
	commit := currentCommit()
	if !validCommitHash(commit) {
		fmt.Fprintln(os.Stderr, "cannot bind evidence to the current git commit")
		os.Exit(2)
	}
	clean, err := worktreeClean()
	if err != nil || (complete && !clean) {
		fmt.Fprintf(os.Stderr, "complete load evidence requires a clean worktree: clean=%t error=%v\n", clean, err)
		os.Exit(2)
	}
	result := report{
		SchemaVersion: 1, Kind: "latchway_load_evidence", StartedAt: time.Now().UTC(),
		Commit: commit, Environment: cfg.Environment, QuotaFixture: cfg.Quota.Fixture,
		Metadata:          cfg.Metadata,
		ProcessExecutable: executable, WorktreeClean: clean, CompleteSuite: complete,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, name := range allGateNames {
		if !selected[name] {
			continue
		}
		var gate gateResult
		switch name {
		case "preflight":
			requestCtx, requestCancel := context.WithTimeout(ctx, cfg.timeout())
			gate = runPreflight(requestCtx, cfg, client)
			requestCancel()
		case "idle":
			gate = runIdleGate(ctx, cfg, pid)
		case "overhead":
			gate = runOverheadGate(ctx, cfg, client)
		case "nonstream":
			gate = runNonStreamGate(ctx, cfg, client)
		case "streams":
			gate = runSSEGate(ctx, cfg, client, pid)
		case "contention":
			gate = runContentionGate(ctx, cfg, client)
		}
		result.Gates = append(result.Gates, gate)
		if name == "preflight" && gate.Status != "passed" {
			break
		}
	}
	if err := writeReport(outputPath, result); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	passed := len(result.Gates) == len(selected)
	for _, gate := range result.Gates {
		passed = passed && gate.Status == "passed"
	}
	if !passed {
		os.Exit(1)
	}
}

func selectedGates(value string) (map[string]bool, bool, error) {
	selected := make(map[string]bool)
	if value == "all" {
		for _, name := range allGateNames {
			selected[name] = true
		}
		return selected, true, nil
	}
	known := make(map[string]bool)
	for _, name := range allGateNames {
		known[name] = true
	}
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if !known[name] {
			return nil, false, fmt.Errorf("unknown gate %q", name)
		}
		selected[name] = true
	}
	if len(selected) == 0 {
		return nil, false, errors.New("at least one gate must be selected")
	}
	return selected, len(selected) == len(allGateNames), nil
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
