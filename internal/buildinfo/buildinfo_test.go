package buildinfo

import (
	"strconv"
	"testing"
)

func TestCanonicalProtocolRange(t *testing.T) {
	t.Parallel()

	if ProtocolVersion != strconv.Itoa(CurrentProtocolVersion) {
		t.Fatalf("protocol string = %q, current = %d", ProtocolVersion, CurrentProtocolVersion)
	}
	versions := SupportedProtocolVersions()
	if len(versions) != 2 || versions[0] != MinimumProtocolVersion || versions[1] != CurrentProtocolVersion {
		t.Fatalf("supported protocol versions = %#v", versions)
	}
	for _, value := range []string{"1", "2"} {
		if !SupportsProtocolVersion(value) {
			t.Errorf("supported protocol version %q was rejected", value)
		}
	}
	for _, value := range []string{"", "0", "01", "3", "1,2"} {
		if SupportsProtocolVersion(value) {
			t.Errorf("unsupported protocol version %q was accepted", value)
		}
	}
}
