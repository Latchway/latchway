package main

import (
	"context"
	"testing"
	"time"
)

func TestValidateListenAddress(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		listen      string
		acknowledge bool
		token       bool
		wantError   bool
	}{
		{name: "IPv4 loopback", listen: "127.0.0.1:19090"},
		{name: "IPv6 loopback", listen: "[::1]:19090"},
		{name: "localhost", listen: "localhost:19090"},
		{name: "isolated exact address", listen: "10.239.100.10:19090", acknowledge: true, token: true},
		{name: "non-loopback missing acknowledgement", listen: "10.239.100.10:19090", token: true, wantError: true},
		{name: "non-loopback missing token", listen: "10.239.100.10:19090", acknowledge: true, wantError: true},
		{name: "wildcard", listen: "0.0.0.0:19090", acknowledge: true, token: true, wantError: true},
		{name: "public address", listen: "8.8.8.8:19090", acknowledge: true, token: true, wantError: true},
		{name: "hostname", listen: "fixture:19090", acknowledge: true, token: true, wantError: true},
		{name: "missing port", listen: "127.0.0.1", wantError: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			err := validateListenAddress(test.listen, test.acknowledge, test.token)
			if (err != nil) != test.wantError {
				t.Fatalf("validateListenAddress() error = %v, wantError=%t", err, test.wantError)
			}
		})
	}
}

func TestDeterministicBarrierReleasesOnlyOnAuthenticatedModeChange(t *testing.T) {
	t.Parallel()
	fixture := &state{}
	fixture.mode.Store("hold-before-response")
	result := make(chan bool, 1)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { result <- fixture.waitWhileMode(ctx, "hold-before-response") }()
	select {
	case <-result:
		t.Fatal("barrier released without a mode change")
	case <-time.After(25 * time.Millisecond):
	}
	fixture.mode.Store("healthy")
	select {
	case released := <-result:
		if !released {
			t.Fatal("barrier reported cancellation after a mode change")
		}
	case <-ctx.Done():
		t.Fatal("barrier did not release after a mode change")
	}
}
