package main

import (
	"bytes"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/latchway/latchway/internal/dpop"
)

func TestPercentileUsesNearestRank(t *testing.T) {
	samples := []time.Duration{5, 1, 4, 2, 3}
	if got := percentile(samples, 0.50); got != 3 {
		t.Fatalf("p50=%s, want 3ns", got)
	}
	if got := percentile(samples, 0.99); got != 5 {
		t.Fatalf("p99=%s, want 5ns", got)
	}
}

func TestMemorySlopeUsesLeastSquares(t *testing.T) {
	origin := time.Unix(1_700_000_000, 0)
	samples := []memorySample{
		{At: origin, MiB: 100},
		{At: origin.Add(30 * time.Second), MiB: 101},
		{At: origin.Add(time.Minute), MiB: 102},
	}
	if got := memorySlopeMiBPerMinute(samples); got < 1.999 || got > 2.001 {
		t.Fatalf("slope=%f, want 2 MiB/min", got)
	}
}

func TestProcessExecutableFromProcCmdline(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name      string
		cmdline   []byte
		want      string
		wantError bool
	}{
		{
			name:    "absolute executable with arguments",
			cmdline: []byte("/latchway\x00serve\x00--role\x00all\x00"),
			want:    "latchway",
		},
		{
			name:    "relative executable",
			cmdline: []byte("latchway\x00serve\x00"),
			want:    "latchway",
		},
		{
			name:    "bounded read ignores large later arguments",
			cmdline: append([]byte("/latchway\x00"), bytes.Repeat([]byte{'a'}, maximumProcArgv0Bytes+100)...),
			want:    "latchway",
		},
		{name: "empty cmdline", wantError: true},
		{name: "empty argv0", cmdline: []byte("\x00serve\x00"), wantError: true},
		{name: "missing NUL delimiter", cmdline: []byte("/latchway"), wantError: true},
		{
			name:      "oversized argv0",
			cmdline:   append(bytes.Repeat([]byte{'a'}, maximumProcArgv0Bytes+1), 0),
			wantError: true,
		},
		{name: "invalid UTF-8", cmdline: []byte{0xff, 0}, wantError: true},
		{name: "control character", cmdline: []byte("/latch\nway\x00"), wantError: true},
		{name: "invalid root basename", cmdline: []byte("/\x00"), wantError: true},
		{
			name:      "oversized basename",
			cmdline:   append([]byte(strings.Repeat("a", maximumProcessNameBytes+1)), 0),
			wantError: true,
		},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got, err := processExecutableFromProcCmdline(bytes.NewReader(test.cmdline))
			if (err != nil) != test.wantError {
				t.Fatalf("processExecutableFromProcCmdline() error = %v, wantError=%t", err, test.wantError)
			}
			if got != test.want {
				t.Fatalf("processExecutableFromProcCmdline() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestProcessExecutableFromProcCmdlineRejectsNilReader(t *testing.T) {
	t.Parallel()
	if _, err := processExecutableFromProcCmdline(nil); err == nil {
		t.Fatal("processExecutableFromProcCmdline(nil) accepted unavailable procfs metadata")
	}
}

func TestNormalizedHTURemovesQueryFragmentAndDefaultPort(t *testing.T) {
	input := mustURL(t, "HTTPS://Example.TEST:443/a/../b?secret=yes#fragment")
	got, err := dpop.NormalizeHTU(input)
	if err != nil {
		t.Fatal(err)
	}
	if got != "https://example.test/b" {
		t.Fatalf("normalized HTU=%q", got)
	}
}

func mustURL(t *testing.T, value string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
