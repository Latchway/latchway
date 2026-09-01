package controlplane

import (
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/id"
)

func TestPageRequestParameters(t *testing.T) {
	t.Parallel()

	if _, _, err := (PageRequest{Size: 50}).parameters(id.Organization); err != nil {
		t.Fatalf("empty cursor error = %v", err)
	}
	instant := time.Date(2026, 8, 27, 12, 0, 0, 0, time.FixedZone("test", 7*60*60))
	identifier, err := id.New(id.Organization)
	if err != nil {
		t.Fatalf("generate organization ID: %v", err)
	}
	timestamp, cursorID, err := (PageRequest{After: instant, AfterID: identifier, Size: 200}).parameters(id.Organization)
	if err != nil {
		t.Fatalf("valid cursor error = %v", err)
	}
	if !timestamp.Valid || !timestamp.Time.Equal(instant) || cursorID == nil || *cursorID != identifier {
		t.Fatalf("unexpected cursor parameters: timestamp=%+v id=%v", timestamp, cursorID)
	}

	invalid := []PageRequest{
		{Size: 0},
		{Size: 201},
		{After: instant, Size: 50},
		{AfterID: identifier, Size: 50},
		{After: instant, AfterID: "app_00000000000000000000000000", Size: 50},
	}
	for _, page := range invalid {
		if _, _, err := page.parameters(id.Organization); err == nil {
			t.Fatalf("parameters(%+v) accepted invalid page", page)
		}
	}
}

func TestValidateLifecycleReason(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"incident review", strings.Repeat("r", 500), "évidence"} {
		if err := validateLifecycleReason(value); err != nil {
			t.Fatalf("validateLifecycleReason(%q) = %v", value, err)
		}
	}
	for _, value := range []string{"", " reason", "reason ", "line\nbreak", "nul\x00byte", strings.Repeat("r", 501), string([]byte{0xff})} {
		if err := validateLifecycleReason(value); err == nil {
			t.Fatalf("validateLifecycleReason(%q) accepted unsafe input", value)
		}
	}
}
