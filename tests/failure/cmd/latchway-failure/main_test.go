package main

import (
	"path/filepath"
	"testing"
)

func TestVersionedFailureMatrixIsStrictAndCoversEveryLiveFaultClass(t *testing.T) {
	path := filepath.Join("..", "..", "matrix.json")
	matrixValue, err := loadMatrix(path)
	if err != nil {
		t.Fatalf("load matrix: %v", err)
	}
	automated := 0
	external := 0
	for _, scenario := range matrixValue.Scenarios {
		switch scenario.Kind {
		case "automated":
			automated++
		case "external":
			external++
		}
	}
	if automated < 9 || external != 6 {
		t.Fatalf("matrix coverage automated=%d external=%d, want at least 9/6", automated, external)
	}
}

func TestGoTestLogRequiresAConcretePassingTest(t *testing.T) {
	passing := []byte("{\"Action\":\"pass\",\"Test\":\"TestExactGate\"}\n{\"Action\":\"pass\"}\n")
	skipped := []byte("{\"Action\":\"skip\",\"Test\":\"TestExactGate\"}\n{\"Action\":\"pass\"}\n")
	if !goTestLogProvesPass(passing) || goTestLogProvesPass(skipped) {
		t.Fatal("go test evidence accepted a skip or rejected a concrete passing test")
	}
}
