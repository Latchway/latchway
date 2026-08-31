package console

import (
	"encoding/json"
	"io/fs"
	"os"
	"strings"
	"testing"
)

func TestAssetsContainManifestEntry(t *testing.T) {
	t.Parallel()

	assets, err := Assets()
	if err != nil {
		t.Fatalf("open embedded console: %v", err)
	}

	for _, name := range []string{"index.html", "SHA256SUMS"} {
		contents, readErr := fs.ReadFile(assets, name)
		if readErr != nil {
			t.Errorf("read %s: %v", name, readErr)
			continue
		}
		if len(contents) == 0 {
			t.Errorf("%s is empty", name)
		}
	}

	manifestBytes, err := fs.ReadFile(assets, "manifest.json")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}

	var manifest map[string]struct {
		File    string `json:"file"`
		IsEntry bool   `json:"isEntry"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}

	entryFile := ""
	for _, asset := range manifest {
		if asset.IsEntry {
			entryFile = asset.File
			break
		}
	}
	if entryFile == "" {
		t.Fatal("manifest has no entry asset")
	}
	if _, err := fs.Stat(assets, entryFile); err != nil {
		t.Fatalf("stat entry asset %q: %v", entryFile, err)
	}
}

func TestDockerConsoleBuildIncludesAdminAPIContract(t *testing.T) {
	t.Parallel()

	dockerfile, err := os.ReadFile("../../Dockerfile")
	if err != nil {
		t.Fatalf("read repository Dockerfile: %v", err)
	}

	const contractCopy = "COPY api/admin.openapi.yaml api/client.openapi.yaml api/config.schema.json /src/api/"
	copyOffset := strings.Index(string(dockerfile), contractCopy)
	if copyOffset < 0 {
		t.Fatalf("Docker console-build stage must include %q", contractCopy)
	}

	goStageOffset := strings.Index(string(dockerfile), " AS go-build")
	if goStageOffset < 0 {
		t.Fatal("Dockerfile has no go-build stage")
	}
	if copyOffset > goStageOffset {
		t.Fatal("Admin OpenAPI contract is copied too late for the console-build stage")
	}
}
