package clientapi

import (
	"net/http"
	"strings"
)

func parseVerifyIdentityRequest(r *http.Request) (VerifyIdentityInput, *requestViolation) {
	object, violation := decodeRequestObject(r, maximumChallengeBodyBytes)
	if violation != nil {
		return VerifyIdentityInput{}, violation
	}
	if !hasExactFields(object, []string{"refresh_token", "identity"}, nil) {
		return VerifyIdentityInput{}, invalidAt("body", "The identity verification object has missing or unsupported fields.")
	}
	refresh, ok := boundedString(object["refresh_token"], 32, 2048)
	if !ok {
		return VerifyIdentityInput{}, invalidAt("body.refresh_token", "refresh_token must satisfy the protocol length limits.")
	}
	identity, ok := object["identity"].(map[string]any)
	if !ok || !hasExactFields(identity, []string{"provider", "token"}, nil) {
		return VerifyIdentityInput{}, invalidAt("body.identity", "identity must contain exactly provider and token.")
	}
	provider, ok := stringMatching(identity["provider"], identifierPattern, 63)
	if !ok {
		return VerifyIdentityInput{}, invalidAt("body.identity.provider", "provider must be a canonical configured identifier.")
	}
	token, ok := boundedString(identity["token"], 1, 64<<10)
	if !ok {
		return VerifyIdentityInput{}, invalidAt("body.identity.token", "token must satisfy the protocol length limits.")
	}
	return VerifyIdentityInput{RefreshToken: NewSensitiveString(refresh), IdentityProvider: provider, IdentityToken: NewSensitiveString(token)}, nil
}

func (api *API) verifySessionIdentity(w http.ResponseWriter, r *http.Request, requestID, logicalRequestID string) {
	declaration, violation := parseClientDeclaration(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	if declaration.protocolVersion != "3" {
		api.writeViolation(w, requestID, &requestViolation{code: "protocol_version_unsupported", detail: "Identity verification requires protocol version 3.", supportedProtocolVersions: []int{3}})
		return
	}
	proof, violation := parseDPoPHeader(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	input, violation := parseVerifyIdentityRequest(r)
	if violation != nil {
		api.writeViolation(w, requestID, violation)
		return
	}
	coordinator, ok := api.coordinator.(IdentityVerificationCoordinator)
	if !ok {
		api.internal(w, requestID)
		return
	}
	input.Metadata = api.metadata(r, logicalRequestID, declaration, http.MethodPost, verifyIdentityPath, proof)
	result, err := coordinator.VerifySessionIdentity(r.Context(), input)
	if err != nil {
		api.writeDependencyFailure(w, requestID, err)
		return
	}
	identity := result.Identity
	if !installationPattern.MatchString(result.InstallationID) || !identifierPattern.MatchString(identity.Provider) || identity.Provider != input.IdentityProvider ||
		identity.Issuer == "" || len(identity.Issuer) > 2048 || identity.Subject == "" || len(identity.Subject) > 2048 || strings.ContainsAny(identity.Issuer+identity.Subject, "\x00\r\n") ||
		len(identity.Audience) == 0 || len(identity.Audience) > 64 || identity.VerifiedAt.IsZero() || !identity.ExpiresAt.After(identity.VerifiedAt) {
		api.internal(w, requestID)
		return
	}
	for _, audience := range identity.Audience {
		if audience == "" || len(audience) > 2048 || strings.ContainsAny(audience, "\x00\r\n") {
			api.internal(w, requestID)
			return
		}
	}
	result.Identity.Audience = append([]string(nil), identity.Audience...)
	api.writeSuccess(w, requestID, http.StatusOK, "no-store", result)
}
