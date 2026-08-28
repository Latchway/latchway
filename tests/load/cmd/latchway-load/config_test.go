package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExampleConfigIsStrictAndMeetsContractFloor(t *testing.T) {
	path := filepath.Join("..", "..", "config", "v1.example.json")
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := decodeConfig(contents)
	if err != nil {
		t.Fatalf("decode example config: %v", err)
	}
	if cfg.Targets.NonStreamRPS != 100 || cfg.Targets.SSEConcurrency != 500 || cfg.Targets.IdleMemoryMiB != 256 ||
		cfg.Targets.P50Milliseconds != 5 || cfg.Targets.P95Milliseconds != 15 || cfg.Targets.P99Milliseconds != 30 {
		t.Fatalf("example config does not preserve v1 target floor: %+v", cfg.Targets)
	}
	if cfg.Quota.ContentionRequest.Method != "POST" || cfg.NonStream.Method != "POST" || cfg.Stream.Method != "POST" {
		t.Fatal("example request methods are not canonical")
	}
	if err := cfg.validate(filepath.Dir(path)); err == nil {
		t.Fatal("example config placeholders must be replaced before a run")
	}
}

func TestSelectedGatesCannotCallSubsetComplete(t *testing.T) {
	selected, complete, err := selectedGates("preflight,overhead")
	if err != nil || complete || len(selected) != 2 {
		t.Fatalf("subset=%v complete=%t error=%v", selected, complete, err)
	}
	selected, complete, err = selectedGates("all")
	if err != nil || !complete || len(selected) != len(allGateNames) {
		t.Fatalf("all=%v complete=%t error=%v", selected, complete, err)
	}
}
