package main

import (
	"net/url"
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
