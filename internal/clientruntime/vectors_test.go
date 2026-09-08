package clientruntime

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCanonicalSharedNativeVectors(t *testing.T) {
	data, err := os.ReadFile("../../api/test-vectors/shared-native/v3.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Contract     string `json:"contract_version"`
		Protocol     int    `json:"wire_protocol"`
		Declarations []struct {
			Protocol, SDK, Caller, Host string
			Valid                       bool
			HostMatches                 bool   `json:"host_matches"`
			FrameworkSDK                string `json:"framework_sdk"`
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Contract != "1.1.0" || vectors.Protocol != 3 || len(vectors.Declarations) < 15 {
		t.Fatal("incomplete vectors")
	}
	for _, row := range vectors.Declarations {
		if (Validate(row.Protocol, row.SDK, row.Caller) == nil) != row.Valid ||
			MatchesHost(row.SDK, row.Caller, row.Host) != row.HostMatches ||
			FrameworkSDK(row.SDK, row.Caller) != row.FrameworkSDK {
			t.Errorf("vector mismatch: %+v", row)
		}
	}
}
