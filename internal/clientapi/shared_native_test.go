package clientapi

import (
	"net/http"
	"testing"
)

func TestSharedNativeDeclarationRequiresV3AndOneCaller(t *testing.T) {
	for _, caller := range []string{"ios", "react-native"} {
		request := validClientRequest(http.MethodPost, challengePath, validChallengeBody("ios"), "native", "1.1.0")
		request.Header.Set("X-Latchway-Protocol-Version", "3")
		request.Header.Set("X-Latchway-Caller", caller)
		declaration, violation := parseClientDeclaration(request)
		if violation != nil || declaration.caller != caller {
			t.Fatalf("%s: %+v", caller, violation)
		}
		request.Header.Set("X-Latchway-Protocol-Version", "2")
		if _, violation := parseClientDeclaration(request); violation == nil {
			t.Fatal("shared SDK accepted wire 2")
		}
		request.Header.Set("X-Latchway-Protocol-Version", "3")
		request.Header.Add("X-Latchway-Caller", caller)
		if _, violation := parseClientDeclaration(request); violation == nil {
			t.Fatal("duplicate caller accepted")
		}
	}
}

func TestSharedNativeFrameworkUsesCallerNotBackend(t *testing.T) {
	request := validClientRequest(http.MethodPost, challengePath, validChallengeBody("ios"), "native", "1.1.0")
	request.Header.Set("X-Latchway-Protocol-Version", "3")
	request.Header.Set("X-Latchway-Caller", "react-native")
	request.Header.Set("X-Latchway-Framework", "react-native-fetch")
	request.Header.Set("X-Latchway-Framework-Version", "1.0.0")
	if _, violation := parseClientDeclaration(request); violation != nil {
		t.Fatalf("RN attribution rejected: %+v", violation)
	}
	request.Header.Set("X-Latchway-Framework", "foundation-models")
	if _, violation := parseClientDeclaration(request); violation == nil {
		t.Fatal("caller/framework mismatch accepted")
	}
	request.Header.Set("X-Latchway-SDK", "ios")
	if _, violation := parseClientDeclaration(request); violation == nil {
		t.Fatal("legacy SDK accepted caller override")
	}
}
