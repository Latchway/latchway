package dataplane

import (
	"context"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/upstream"
)

var secretReferencePattern = regexp.MustCompile(`^secret/[a-z][a-z0-9_-]{0,62}$`)

func buildProtectedTarget(config configuration.Upstream) (cachedDispatchTarget, error) {
	if _, err := protectedTargetKey(config); err != nil {
		return nil, err
	}
	traceContextPropagation, err := configuredTraceContextPropagation(config.TraceContextPropagation)
	if err != nil {
		return nil, err
	}
	target, err := upstream.NewTarget(
		config.BaseURL,
		upstream.DestinationPolicy{
			AllowPrivate: config.DestinationPolicy.AllowPrivateNetworks,
			AllowedCIDRs: append([]netip.Prefix(nil), config.DestinationPolicy.AllowedCIDRs...),
		},
		upstream.Timeouts{
			Connect: config.Timeouts.Connect, TLSHandshake: config.Timeouts.Connect,
			ResponseHeader: config.Timeouts.ResponseHeader, IdleConnection: config.Timeouts.Idle,
		},
		nil,
	)
	if err != nil {
		return nil, errTargetConfiguration
	}
	return &protectedDispatchTarget{target: target, traceContextPropagation: traceContextPropagation}, nil
}

func validTargetTimeouts(value configuration.UpstreamTimeouts) bool {
	return value.Connect > 0 && value.ResponseHeader > 0 && value.FirstByte > 0 && value.Idle > 0 && value.Total > 0 &&
		value.Total <= 10*time.Minute && value.Connect <= value.Total &&
		value.ResponseHeader <= value.Total && value.FirstByte <= value.Total && value.Idle <= value.Total
}

func validUpstreamAuthentication(value configuration.UpstreamAuthentication) bool {
	switch value.Type {
	case "none":
		return value.SecretRef == "" && value.HeaderName == "" && value.Username == "" && len(value.Headers) == 0
	case "bearer":
		return secretReferencePattern.MatchString(value.SecretRef) && value.HeaderName == "" &&
			value.Username == "" && len(value.Headers) == 0
	case "header":
		return secretReferencePattern.MatchString(value.SecretRef) && validCredentialHeaderName(value.HeaderName) &&
			value.Username == "" && len(value.Headers) == 0
	case "basic":
		return secretReferencePattern.MatchString(value.SecretRef) && value.HeaderName == "" &&
			validBasicAuthenticationUsername(value.Username) && len(value.Headers) == 0
	case "headers":
		if value.SecretRef != "" || value.HeaderName != "" || value.Username != "" ||
			len(value.Headers) < 1 || len(value.Headers) > 8 {
			return false
		}
		seen := make(map[string]struct{}, len(value.Headers))
		for _, header := range value.Headers {
			canonical := http.CanonicalHeaderKey(header.HeaderName)
			if !secretReferencePattern.MatchString(header.SecretRef) || !validCredentialHeaderName(header.HeaderName) {
				return false
			}
			if _, duplicate := seen[canonical]; duplicate {
				return false
			}
			seen[canonical] = struct{}{}
		}
		return true
	default:
		return false
	}
}

func validCredentialHeaderName(name string) bool {
	if name == "" || len(name) > 256 || strings.TrimSpace(name) != name {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if (character < 'a' || character > 'z') && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') && !strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character)) {
			return false
		}
	}
	canonical := http.CanonicalHeaderKey(name)
	if strings.HasPrefix(strings.ToLower(canonical), "x-latchway-") {
		return false
	}
	switch canonical {
	case "Accept", "Accept-Encoding", "Anthropic-Version", "Baggage", "Connection", "Content-Encoding", "Content-Length", "Content-Type", "Cookie", "Dpop", "Dpop-Nonce", "Expect", "Forwarded", "Host", "Keep-Alive",
		"Proxy-Authorization", "Proxy-Connection", "Set-Cookie", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
		"Traceparent", "Tracestate",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto":
		return false
	default:
		return true
	}
}

func validBasicAuthenticationUsername(username string) bool {
	if len(username) == 0 || len(username) > 256 {
		return false
	}
	for index := 0; index < len(username); index++ {
		character := username[index]
		if character < 0x21 || character > 0x7e || character == ':' {
			return false
		}
	}
	return true
}

type protectedDispatchTarget struct {
	target                  *upstream.Target
	traceContextPropagation upstream.TraceContextPropagation
}

func configuredTraceContextPropagation(value string) (upstream.TraceContextPropagation, error) {
	switch value {
	case configuration.TraceContextPropagationNone:
		return upstream.TraceContextPropagationNone, nil
	case configuration.TraceContextPropagationW3C:
		return upstream.TraceContextPropagationW3C, nil
	default:
		return upstream.TraceContextPropagationNone, errTargetConfiguration
	}
}

func (target *protectedDispatchTarget) Prepare(
	incoming *http.Request,
	requestPath string,
	forwardedHeaders []string,
	staticHeaders map[string]string,
) (ProviderRequest, error) {
	if target == nil || target.target == nil {
		return ProviderRequest{}, errTargetConfiguration
	}
	prepared, err := upstream.PrepareRequest(
		incoming, target.target, requestPath, forwardedHeaders, staticHeaders, target.traceContextPropagation,
	)
	if err != nil {
		return ProviderRequest{}, err
	}
	return ProviderRequest{native: prepared}, nil
}

func (target *protectedDispatchTarget) DispatchWithBeforeRoundTrip(
	ctx context.Context,
	request ProviderRequest,
	beforeRoundTrip func() error,
) (*upstream.DispatchedResponse, error) {
	if target == nil || target.target == nil {
		return nil, errTargetConfiguration
	}
	return target.target.DispatchWithBeforeRoundTrip(ctx, request.native, beforeRoundTrip)
}

func (target *protectedDispatchTarget) WithBearerDispatchWithBeforeRoundTrip(
	ctx context.Context,
	request ProviderRequest,
	credential []byte,
	beforeRoundTrip func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	if target == nil || target.target == nil {
		return errTargetConfiguration
	}
	return target.target.WithBearerDispatchWithBeforeRoundTrip(
		ctx, request.native, credential, beforeRoundTrip, consume,
	)
}

func (target *protectedDispatchTarget) WithHeaderDispatchWithBeforeRoundTrip(
	ctx context.Context,
	request ProviderRequest,
	name string,
	credential []byte,
	beforeRoundTrip func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	if target == nil || target.target == nil {
		return errTargetConfiguration
	}
	return target.target.WithHeaderDispatchWithBeforeRoundTrip(
		ctx, request.native, name, credential, beforeRoundTrip, consume,
	)
}

func (target *protectedDispatchTarget) WithBasicDispatchWithBeforeRoundTrip(
	ctx context.Context,
	request ProviderRequest,
	username string,
	credential []byte,
	beforeRoundTrip func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	if target == nil || target.target == nil {
		return errTargetConfiguration
	}
	return target.target.WithBasicDispatchWithBeforeRoundTrip(
		ctx, request.native, username, credential, beforeRoundTrip, consume,
	)
}

func (target *protectedDispatchTarget) WithHeadersDispatchWithBeforeRoundTrip(
	ctx context.Context,
	request ProviderRequest,
	credentials []upstream.HeaderCredential,
	beforeRoundTrip func() error,
	consume func(*upstream.DispatchedResponse) error,
) error {
	if target == nil || target.target == nil {
		return errTargetConfiguration
	}
	return target.target.WithHeadersDispatchWithBeforeRoundTrip(
		ctx, request.native, credentials, beforeRoundTrip, consume,
	)
}

func (target *protectedDispatchTarget) CloseIdleConnections() {
	if target != nil && target.target != nil {
		target.target.CloseIdleConnections()
	}
}
