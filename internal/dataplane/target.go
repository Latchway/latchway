package dataplane

import (
	"context"
	"net/http"
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
	target, err := upstream.NewTarget(
		config.BaseURL,
		upstream.DestinationPolicy{AllowPrivate: false},
		upstream.Timeouts{
			Connect: config.Timeouts.Connect, TLSHandshake: config.Timeouts.Connect,
			ResponseHeader: config.Timeouts.FirstByte, IdleConnection: config.Timeouts.Idle,
		},
		nil,
	)
	if err != nil {
		return nil, errTargetConfiguration
	}
	return &protectedDispatchTarget{target: target}, nil
}

func validTargetTimeouts(value configuration.UpstreamTimeouts) bool {
	return value.Connect > 0 && value.FirstByte > 0 && value.Idle > 0 && value.Total > 0 &&
		value.Total <= 10*time.Minute && value.Connect <= value.Total &&
		value.FirstByte <= value.Total && value.Idle <= value.Total
}

func validUpstreamAuthentication(value configuration.UpstreamAuthentication) bool {
	switch value.Type {
	case "none":
		return value.SecretRef == "" && value.HeaderName == ""
	case "bearer":
		return secretReferencePattern.MatchString(value.SecretRef) && value.HeaderName == ""
	case "header":
		return secretReferencePattern.MatchString(value.SecretRef) && validCredentialHeaderName(value.HeaderName)
	default:
		return false
	}
}

func validCredentialHeaderName(name string) bool {
	if name == "" || strings.TrimSpace(name) != name {
		return false
	}
	for index := 0; index < len(name); index++ {
		character := name[index]
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))) {
			return false
		}
	}
	canonical := http.CanonicalHeaderKey(name)
	if strings.HasPrefix(strings.ToLower(canonical), "x-latchway-") {
		return false
	}
	switch canonical {
	case "Accept", "Accept-Encoding", "Connection", "Content-Encoding", "Content-Length", "Content-Type", "Cookie", "Dpop", "Dpop-Nonce", "Expect", "Forwarded", "Host", "Keep-Alive",
		"Proxy-Authorization", "Proxy-Connection", "Set-Cookie", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto":
		return false
	default:
		return true
	}
}

type protectedDispatchTarget struct {
	target *upstream.Target
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
	prepared, err := upstream.PrepareRequest(incoming, target.target, requestPath, forwardedHeaders, staticHeaders)
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

func (target *protectedDispatchTarget) CloseIdleConnections() {
	if target != nil && target.target != nil {
		target.target.CloseIdleConnections()
	}
}
