package dataplane

import "testing"

func TestIsolatedVerificationTargetFactoryRequiresPublicConfiguredAndExactPrivateReplacement(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		configured   string
		replacement  string
		wantAccepted bool
	}{
		{
			name: "bounded private address", configured: "https://provider.example/v1",
			replacement: "http://10.23.45.67:8080/v1", wantAccepted: true,
		},
		{name: "configured loopback", configured: "http://127.0.0.1:8080/v1", replacement: "http://10.23.45.67:8080/v1"},
		{name: "replacement loopback", configured: "https://provider.example/v1", replacement: "http://127.0.0.1:8080/v1"},
		{name: "replacement public", configured: "https://provider.example/v1", replacement: "http://203.0.113.8:8080/v1"},
		{name: "replacement hostname", configured: "https://provider.example/v1", replacement: "http://private.example:8080/v1"},
		{name: "replacement TLS", configured: "https://provider.example/v1", replacement: "https://10.23.45.67:8080/v1"},
		{name: "replacement query", configured: "https://provider.example/v1", replacement: "http://10.23.45.67:8080/v1?unsafe=1"},
		{name: "replacement invalid port", configured: "https://provider.example/v1", replacement: "http://10.23.45.67:99999/v1"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory, err := NewIsolatedVerificationTargetFactory(map[string]string{
				test.configured: test.replacement,
			})
			if test.wantAccepted {
				if err != nil || factory == nil {
					t.Fatalf("factory = %v, error = %v", factory, err)
				}
				return
			}
			if err == nil || factory != nil {
				t.Fatalf("factory = %v, error = %v, want rejection", factory, err)
			}
		})
	}
}

func TestIsolatedVerificationTargetFactoryRejectsEmptyMap(t *testing.T) {
	t.Parallel()
	if factory, err := NewIsolatedVerificationTargetFactory(nil); err == nil || factory != nil {
		t.Fatalf("factory = %v, error = %v, want rejection", factory, err)
	}
}
