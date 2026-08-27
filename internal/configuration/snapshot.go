package configuration

import (
	"encoding/json"
	"fmt"
	"time"
)

type compiledSnapshotDocument struct {
	Spec struct {
		Session struct {
			AccessTokenTTL          string `json:"accessTokenTtl"`
			ChallengeTTL            string `json:"challengeTtl"`
			RefreshTokenTTL         string `json:"refreshTokenTtl"`
			MaximumClockSkewSeconds *int   `json:"maximumClockSkewSeconds"`
		} `json:"session"`
		IdentityProviders []IdentityProvider `json:"identityProviders"`
		AttestationPolicy []struct {
			ID        string                         `json:"id"`
			MaxAge    string                         `json:"maxAge"`
			Platforms map[string]PlatformAttestation `json:"platforms"`
		} `json:"attestationPolicies"`
		Upstreams  []compiledUpstream  `json:"upstreams"`
		Models     []compiledModel     `json:"models"`
		LimitPlans []compiledLimitPlan `json:"limitPlans"`
		Features   []compiledFeature   `json:"features"`
	} `json:"spec"`
}

func newActiveSnapshot(revisionID, environmentID string, document, compiled json.RawMessage) (ActiveSnapshot, error) {
	var parsed compiledSnapshotDocument
	if err := json.Unmarshal(compiled, &parsed); err != nil {
		return ActiveSnapshot{}, fmt.Errorf("decode compiled active configuration: %w", err)
	}
	session, err := compiledSessionPolicy(parsed)
	if err != nil {
		return ActiveSnapshot{}, err
	}
	snapshot := ActiveSnapshot{
		RevisionID: revisionID, EnvironmentID: environmentID,
		document:     append(json.RawMessage(nil), document...),
		compiled:     append(json.RawMessage(nil), compiled...),
		session:      session,
		identities:   make(map[string]IdentityProvider, len(parsed.Spec.IdentityProviders)),
		attestations: make(map[string]AttestationPolicy, len(parsed.Spec.AttestationPolicy)),
		upstreams:    make(map[string]Upstream, len(parsed.Spec.Upstreams)),
		models:       make(map[string]Model, len(parsed.Spec.Models)),
		limitPlans:   make(map[string]LimitPlan, len(parsed.Spec.LimitPlans)),
		features:     make(map[string]Feature, len(parsed.Spec.Features)),
	}
	for _, provider := range parsed.Spec.IdentityProviders {
		if provider.ID == "" {
			return ActiveSnapshot{}, errorsCorruptSnapshot("identity provider ID")
		}
		snapshot.identities[provider.ID] = provider.clone()
	}
	for _, rawPolicy := range parsed.Spec.AttestationPolicy {
		if rawPolicy.ID == "" {
			return ActiveSnapshot{}, errorsCorruptSnapshot("attestation policy ID")
		}
		maxAge := defaultAttestationAge
		if rawPolicy.MaxAge != "" {
			maxAge, err = parseConfigDuration(rawPolicy.MaxAge)
			if err != nil {
				return ActiveSnapshot{}, errorsCorruptSnapshot("attestation maximum age")
			}
		}
		policy := AttestationPolicy{ID: rawPolicy.ID, MaxAge: maxAge, Platforms: make(map[string]PlatformAttestation, len(rawPolicy.Platforms))}
		for platform, selection := range rawPolicy.Platforms {
			policy.Platforms[platform] = selection.clone()
		}
		snapshot.attestations[policy.ID] = policy
	}
	if err := snapshot.loadRuntimeConfiguration(parsed.Spec.Upstreams, parsed.Spec.Models, parsed.Spec.LimitPlans, parsed.Spec.Features); err != nil {
		return ActiveSnapshot{}, err
	}
	return snapshot, nil
}

func compiledSessionPolicy(document compiledSnapshotDocument) (SessionPolicy, error) {
	result := SessionPolicy{
		AccessTokenTTL: defaultAccessTokenTTL, ChallengeTTL: defaultChallengeTTL,
		RefreshTokenTTL: defaultRefreshTokenTTL, MaximumClockSkew: defaultClockSkew,
	}
	values := []struct {
		raw         string
		destination *time.Duration
		name        string
	}{
		{raw: document.Spec.Session.AccessTokenTTL, destination: &result.AccessTokenTTL, name: "access-token TTL"},
		{raw: document.Spec.Session.ChallengeTTL, destination: &result.ChallengeTTL, name: "challenge TTL"},
		{raw: document.Spec.Session.RefreshTokenTTL, destination: &result.RefreshTokenTTL, name: "refresh-token TTL"},
	}
	for _, value := range values {
		if value.raw == "" {
			continue
		}
		parsed, err := parseConfigDuration(value.raw)
		if err != nil {
			return SessionPolicy{}, errorsCorruptSnapshot(value.name)
		}
		*value.destination = parsed
	}
	if document.Spec.Session.MaximumClockSkewSeconds != nil {
		result.MaximumClockSkew = time.Duration(*document.Spec.Session.MaximumClockSkewSeconds) * time.Second
	}
	if result.AccessTokenTTL < time.Minute || result.AccessTokenTTL > time.Hour ||
		result.ChallengeTTL < 30*time.Second || result.ChallengeTTL > 10*time.Minute ||
		result.RefreshTokenTTL < time.Hour || result.RefreshTokenTTL > 90*24*time.Hour ||
		result.MaximumClockSkew < 0 || result.MaximumClockSkew > 5*time.Minute {
		return SessionPolicy{}, errorsCorruptSnapshot("session policy bounds")
	}
	return result, nil
}

func errorsCorruptSnapshot(field string) error {
	return fmt.Errorf("compiled active configuration has invalid %s", field)
}
