package session

import (
	"errors"
	"testing"

	"github.com/latchway/latchway/internal/clientruntime"
)

func TestSharedNativeAccessPolicyDoesNotConsumeRejectedProofPostgreSQL(t *testing.T) {
	f := newAccessRevocationFixture(t, "ios", "react-native")
	input := AccessRequestInput{
		AccessToken: f.issued.Access.Token, Principal: f.principal,
		DPoPProof: signedSessionAccessDPoP(t, f.key, "DELETE", f.revokeURI, f.now,
			f.issued.Access.Token.Reveal(), "shared-policy-same-request"),
		HTTPMethod: "DELETE", RequestURI: f.revokeURI,
		Runtime: clientruntime.Declaration{Protocol: "3", SDK: "native", Caller: "android"},
	}
	if _, err := f.store.AuthorizeAccess(f.ctx, input); !errors.Is(err, ErrClientRuntime) {
		t.Fatalf("wrong host caller: %v", err)
	}
	input.Runtime.Caller = "react-native"
	if _, err := f.store.AuthorizeAccess(f.ctx, input); err != nil {
		t.Fatalf("allowed RN caller on same native session/proof: %v", err)
	}
	if _, err := f.store.AuthorizeAccess(f.ctx, input); !errors.Is(err, ErrDPoPReplayed) {
		t.Fatalf("proof replay was not rejected: %v", err)
	}
}

func TestSharedNativeRefreshRequiresOptInWithoutRotatingOnDenialPostgreSQL(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy-policy", true: "explicit-opt-in"}[enabled], func(t *testing.T) {
			var callers []string
			if enabled {
				callers = []string{"ios", "react-native"}
			}
			f := newAccessRevocationFixture(t, callers...)
			input := RotateInput{
				RefreshToken: f.issued.Refresh,
				DPoPProof:    signedSessionDPoP(t, f.key, "POST", f.refreshURI, f.now, "shared-refresh-proof"),
				HTTPMethod:   "POST", RequestURI: f.refreshURI,
				Runtime: clientruntime.Declaration{Protocol: "3", SDK: "native", Caller: "react-native"},
			}
			if enabled {
				if _, err := f.store.Rotate(f.ctx, input); err != nil {
					t.Fatalf("shared refresh: %v", err)
				}
				return
			}
			if _, err := f.store.Rotate(f.ctx, input); !errors.Is(err, ErrClientRuntime) {
				t.Fatalf("implicit opt-in accepted: %v", err)
			}
			input.Runtime = clientruntime.Declaration{Protocol: "2", SDK: "ios"}
			if _, err := f.store.Rotate(f.ctx, input); err != nil {
				t.Fatalf("denial consumed legacy refresh token/proof: %v", err)
			}
		})
	}
}

func TestSharedNativeDelegatedSessionPolicyPostgreSQL(t *testing.T) {
	for _, scenario := range []struct {
		definition string
		shared     bool
	}{{"ios-widget", true}, {"watch", true}, {"ios-widget", false}} {
		name := scenario.definition
		if !scenario.shared {
			name += "-legacy-policy"
		}
		t.Run(name, func(t *testing.T) {
			definition := scenario.definition
			var callers []string
			rootRuntime := clientruntime.Declaration{Protocol: "2", SDK: "ios"}
			if scenario.shared {
				callers = []string{"ios", "react-native"}
				rootRuntime = clientruntime.Declaration{Protocol: "3", SDK: "native", Caller: "react-native"}
			}
			f := newAccessRevocationFixtureWithComponents(t, true, callers...)
			childKey, childJWK, childJKT := newChallengeKey(t)
			provisionURI := mustSessionURL(t, "https://gateway.example.test/client/v1/installation-families/current/components")
			provisioned, err := f.store.ProvisionComponent(f.ctx, ComponentProvisionInput{
				Access: AccessRequestInput{AccessToken: f.issued.Access.Token, Principal: f.principal,
					DPoPProof:  signedSessionAccessDPoP(t, f.key, "POST", provisionURI, f.now, f.issued.Access.Token.Reveal(), "shared-provision"),
					HTTPMethod: "POST", RequestURI: provisionURI,
					Runtime: rootRuntime},
				DefinitionID: definition, PublicJWK: childJWK, RequestedFeatures: []string{"assistant"}, AppVersion: "1", SDKVersion: "1.2.0-dev",
			})
			if err != nil {
				t.Fatalf("provision independent component: %v", err)
			}
			exchangeURI := mustSessionURL(t, "https://gateway.example.test/client/v1/component-sessions")
			input := ComponentSessionInput{ComponentID: provisioned.Component.ID, RefreshGrant: provisioned.RefreshGrant,
				DPoPProof: signedSessionDPoP(t, childKey, "POST", exchangeURI, f.now, "child-exchange"), HTTPMethod: "POST", RequestURI: exchangeURI,
				Runtime: clientruntime.Declaration{Protocol: "3", SDK: "native", Caller: "android"}}
			if _, err := f.store.CreateComponentSession(f.ctx, input); !errors.Is(err, ErrClientRuntime) {
				t.Fatalf("wrong host caller: %v", err)
			}
			input.Runtime.Caller = "react-native"
			if definition == "watch" || !scenario.shared {
				if _, err := f.store.CreateComponentSession(f.ctx, input); !errors.Is(err, ErrClientRuntime) {
					t.Fatalf("remote/legacy component policy silently adopted: %v", err)
				}
				input.Runtime = clientruntime.Declaration{Protocol: "2", SDK: "ios"}
			}
			child, err := f.store.CreateComponentSession(f.ctx, input)
			if err != nil {
				t.Fatalf("denial consumed component grant/proof: %v", err)
			}
			principal, err := f.verifier.Verify(f.ctx, child.Access.Token)
			if err != nil || principal.DPoPJKT != childJKT || principal.ComponentIsRoot || principal.ApplicationUserID != f.principal.ApplicationUserID {
				t.Fatalf("component lost independent key/user binding: %v", err)
			}
			if definition == "watch" || !scenario.shared {
				return
			}
			access := AccessRequestInput{AccessToken: child.Access.Token, Principal: principal,
				DPoPProof:  signedSessionAccessDPoP(t, childKey, "DELETE", f.revokeURI, f.now, child.Access.Token.Reveal(), "child-access"),
				HTTPMethod: "DELETE", RequestURI: f.revokeURI, Runtime: clientruntime.Declaration{Protocol: "3", SDK: "native", Caller: "android"}}
			if _, err := f.store.AuthorizeAccess(f.ctx, access); !errors.Is(err, ErrClientRuntime) {
				t.Fatalf("wrong caller access: %v", err)
			}
			access.Runtime.Caller = "ios"
			if _, err := f.store.AuthorizeAccess(f.ctx, access); err != nil {
				t.Fatalf("component native access after denial: %v", err)
			}
			rotate := RotateInput{RefreshToken: child.Refresh,
				DPoPProof: signedSessionDPoP(t, childKey, "POST", f.refreshURI, f.now, "child-refresh"), HTTPMethod: "POST", RequestURI: f.refreshURI,
				Runtime: clientruntime.Declaration{Protocol: "3", SDK: "native", Caller: "android"}}
			if _, err := f.store.Rotate(f.ctx, rotate); !errors.Is(err, ErrClientRuntime) {
				t.Fatalf("wrong caller refresh: %v", err)
			}
			rotate.Runtime.Caller = "react-native"
			if _, err := f.store.Rotate(f.ctx, rotate); err != nil {
				t.Fatalf("component shared refresh after denial: %v", err)
			}
		})
	}
}
