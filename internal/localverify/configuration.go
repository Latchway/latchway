package localverify

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/protocol"
	"github.com/latchway/latchway/internal/quota"
)

const (
	inputProfileID            = "bounded_chat"
	pricingID                 = "local_verify_prices"
	assistantPlan             = "assistant_limits"
	outputPlan                = "output_limits"
	pacePlan                  = "pace_limits"
	streamPlan                = "stream_limits"
	fallbackPlan              = "fallback_limits"
	developmentInputProfileID = "bounded_responses"
	developmentPlan           = "habit_assistant_limits"
	developmentPricingID      = "local_development_prices"
	developmentModel          = "assistant_default"
	developmentFeature        = "habit-assistant"
)

func (f *fixture) configurationDocument() ([]byte, error) {
	if f.oidc == nil {
		return nil, errors.New("mock OIDC issuer is unavailable")
	}
	models := []any{
		modelDocument("chat", "primary"),
		modelDocument("fallback_primary", "failure"),
		modelDocument("fallback_secondary", "fallback"),
	}
	pricingEntries := make([]any, 0, len(models))
	for _, model := range []string{"chat", "fallback_primary", "fallback_secondary"} {
		pricingEntries = append(pricingEntries, map[string]any{
			"model": model, "inputNanoUsdPerMillion": int64(0),
			"outputNanoUsdPerMillion": int64(0), "requestNanoUsd": int64(0),
		})
	}
	document := map[string]any{
		"apiVersion": "latchway.dev/v1alpha1",
		"kind":       "EnvironmentConfig",
		"metadata": map[string]any{
			"organization": "local-verify", "application": "mobile-app", "environment": "development",
		},
		"spec": map[string]any{
			"identityProviders": []any{map[string]any{
				"id": "mock_oidc", "type": "generic_oidc", "issuer": f.oidc.issuer,
				"audiences": []any{oidcAudience}, "allowedAlgorithms": []any{"RS256"},
				"jwksUrl": f.oidc.jwksURL, "subjectClaim": "sub", "clockSkewSeconds": 0,
				"claimMappings": map[string]any{"tier": "claims.tier"},
			}},
			"attestationPolicies": []any{map[string]any{
				"id": "native", "maxAge": "10m",
				"platforms": map[string]any{"react_native_ios": map[string]any{
					"provider": "debug", "mode": "required", "minimumTrustLevel": "debug",
					"secretRef": "secret/debug-attestation-public-keys",
				}},
			}},
			"componentDefinitions": []any{map[string]any{
				"id": "react-native-ios-main", "platform": "react_native_ios", "kind": "main_app",
				"identifiers": map[string]any{"bundleIdentifiers": []any{"dev.latchway.local-verify"}},
				"familyRole":  "root",
				"attestation": map[string]any{"strategy": "direct", "provider": "debug"},
				"allowedFeatures": []any{
					"assistant", "output_guard", "request_pacer", "stream_guard", "fallback",
				},
			}},
			"upstreams": []any{
				upstreamDocument("primary", configuredPrimary),
				upstreamDocument("failure", configuredFailure),
				upstreamDocument("fallback", configuredFallback),
			},
			"inputAccountingProfiles": []any{map[string]any{
				"id": inputProfileID, "protocol": protocol.OpenAIChatID,
				"method": quota.UTF8ByteBPEDeclaredFramingV1, "physicalModel": providerModel,
				"maximumFramingTokensPerRequest": int64(8),
				"maximumFramingTokensPerMessage": int64(4),
				"maximumContextTokens":           int64(4096),
			}},
			"models": models,
			"pricingCatalogs": []any{map[string]any{
				"id": pricingID, "currency": quota.USDCurrency,
				"effectiveAt": "2020-01-01T00:00:00Z", "entries": pricingEntries,
			}},
			"limitPlans": []any{
				map[string]any{"id": assistantPlan, "limits": []any{
					calendarLimit(quota.LogicalRequestsMetric, []any{"feature", "user"}, "1d", 2),
					calendarLimit(quota.InputTokensMetric, []any{"feature", "user"}, "1d", 100_000),
					calendarLimit(quota.OutputTokensMetric, []any{"feature", "user"}, "1d", 100_000),
					calendarLimit(quota.TotalTokensMetric, []any{"feature", "user"}, "1d", 200_000),
					perRequestLimit(quota.InputTokensMetric, []any{"feature", "user"}, 4096),
					perRequestLimit(quota.OutputTokensMetric, []any{"feature", "user"}, 8),
					perRequestLimit(quota.TotalTokensMetric, []any{"feature", "user"}, 4104),
				}},
				map[string]any{"id": outputPlan, "limits": []any{
					calendarLimit(quota.OutputTokensMetric, []any{"feature", "user"}, "1d", 7),
					perRequestLimit(quota.OutputTokensMetric, []any{"feature", "user"}, 7),
				}},
				map[string]any{"id": pacePlan, "limits": []any{map[string]any{
					"metric": quota.LogicalRequestsMetric, "algorithm": quota.TokenBucketAlgorithm,
					"scope": []any{"feature", "user"}, "capacity": int64(1),
					"refillPerSecond": json.Number("0.01"), "hard": true,
				}}},
				map[string]any{"id": streamPlan, "limits": []any{map[string]any{
					"metric": quota.ConcurrentStreamsMetric, "algorithm": quota.ConcurrencyAlgorithm,
					"scope": []any{"environment", "feature"}, "maximum": int64(1), "hard": true,
				}}},
				map[string]any{"id": fallbackPlan, "limits": []any{
					calendarLimit(quota.LogicalRequestsMetric, []any{"feature", "user"}, "1d", 5),
				}},
			},
			"features": []any{
				featureDocument("assistant", assistantPlan, 8, []any{routeDocument("primary", "chat", 10, nil)}),
				featureDocument("output_guard", outputPlan, 7, []any{routeDocument("primary", "chat", 10, nil)}),
				featureDocument("request_pacer", pacePlan, 8, []any{routeDocument("primary", "chat", 10, nil)}),
				featureDocument("stream_guard", streamPlan, 8, []any{routeDocument("primary", "chat", 10, nil)}),
				featureDocument("fallback", fallbackPlan, 8, []any{
					routeDocument("failure", "fallback_primary", 10, []any{"status_500"}),
					routeDocument("fallback", "fallback_secondary", 20, nil),
				}),
			},
		},
	}
	return json.Marshal(document)
}

func (f *fixture) developmentConfigurationDocument() ([]byte, error) {
	if f.oidc == nil || f.browserOrigin == "" {
		return nil, errors.New("local development identity or browser origin is unavailable")
	}
	debugSelection := func() map[string]any {
		return map[string]any{
			"provider": "debug", "mode": "required", "minimumTrustLevel": "debug",
			"secretRef": "secret/debug-attestation-public-keys",
		}
	}
	platforms := map[string]any{}
	for _, platform := range []string{"ios", "android", "react_native_ios", "react_native_android"} {
		platforms[platform] = debugSelection()
	}
	webSelection := debugSelection()
	webSelection["allowedOrigins"] = []any{f.browserOrigin}
	platforms["web"] = webSelection

	component := func(identifier, platform, kind string, identifiers map[string]any) map[string]any {
		return map[string]any{
			"id": identifier, "platform": platform, "kind": kind, "identifiers": identifiers,
			"familyRole":      "root",
			"attestation":     map[string]any{"strategy": "direct", "provider": "debug"},
			"allowedFeatures": []any{developmentFeature},
		}
	}
	document := map[string]any{
		"apiVersion": "latchway.dev/v1alpha1",
		"kind":       "EnvironmentConfig",
		"metadata": map[string]any{
			"organization": "local-verify", "application": "mobile-app", "environment": "development",
		},
		"spec": map[string]any{
			"identityProviders": []any{map[string]any{
				"id": "mock_oidc", "type": "generic_oidc", "issuer": f.oidc.issuer,
				"audiences": []any{oidcAudience}, "allowedAlgorithms": []any{"RS256"},
				"jwksUrl": f.oidc.jwksURL, "subjectClaim": "sub", "clockSkewSeconds": 30,
				"claimMappings": map[string]any{"tier": "claims.tier"},
			}},
			"attestationPolicies": []any{map[string]any{
				"id": "development-clients", "maxAge": "10m", "platforms": platforms,
			}},
			"componentDefinitions": []any{
				component("ios-main", "ios", "main_app", map[string]any{"bundleIdentifiers": []any{"dev.latchway.quickstart.ios"}}),
				component("android-main", "android", "android_app", map[string]any{"packageNames": []any{"dev.latchway.quickstart.android"}}),
				component("web-browser", "web", "browser", map[string]any{"origins": []any{f.browserOrigin}}),
				component("react-native-ios-main", "react_native_ios", "main_app", map[string]any{"bundleIdentifiers": []any{"dev.latchway"}}),
				component("react-native-android-main", "react_native_android", "android_app", map[string]any{"packageNames": []any{"dev.latchway.reactnative"}}),
			},
			"upstreams": []any{upstreamDocument("primary", configuredPrimary)},
			"inputAccountingProfiles": []any{map[string]any{
				"id": developmentInputProfileID, "protocol": protocol.OpenAIResponsesID,
				"method": quota.UTF8ByteBPEDeclaredFramingV1, "physicalModel": providerModel,
				"maximumFramingTokensPerRequest": int64(8),
				"maximumFramingTokensPerMessage": int64(4),
				"maximumContextTokens":           int64(4096),
			}},
			"models": []any{map[string]any{
				"id": developmentModel, "upstream": "primary", "upstreamModel": providerModel,
				"pricingRef": developmentPricingID, "inputAccountingRef": developmentInputProfileID,
				"capabilities": []any{protocol.OpenAIResponsesID},
			}},
			"pricingCatalogs": []any{map[string]any{
				"id": developmentPricingID, "currency": quota.USDCurrency,
				"effectiveAt": "2020-01-01T00:00:00Z", "entries": []any{map[string]any{
					"model": developmentModel, "inputNanoUsdPerMillion": int64(0),
					"outputNanoUsdPerMillion": int64(0), "requestNanoUsd": int64(0),
				}},
			}},
			"limitPlans": []any{map[string]any{
				"id": developmentPlan, "limits": []any{
					calendarLimit(quota.LogicalRequestsMetric, []any{"feature", "user"}, "1d", 100),
					calendarLimit(quota.InputTokensMetric, []any{"feature", "user"}, "1d", 1_000_000),
					calendarLimit(quota.OutputTokensMetric, []any{"feature", "user"}, "1d", 1_000_000),
					calendarLimit(quota.TotalTokensMetric, []any{"feature", "user"}, "1d", 2_000_000),
					perRequestLimit(quota.InputTokensMetric, []any{"feature", "user"}, 4096),
					perRequestLimit(quota.OutputTokensMetric, []any{"feature", "user"}, 256),
					perRequestLimit(quota.TotalTokensMetric, []any{"feature", "user"}, 4352),
				},
			}},
			"features": []any{map[string]any{
				"id": developmentFeature, "protocol": protocol.OpenAIResponsesID,
				"attestationPolicy": "development-clients",
				"access":            map[string]any{"expression": "principal.authenticated && principal.claims.tier == 'pro'"},
				"limitPlan":         map[string]any{"expression": "'" + developmentPlan + "'"},
				"output":            map[string]any{"defaultMaximumTokens": int64(128), "absoluteMaximumTokens": int64(256)},
				"routes":            []any{routeDocument("primary", developmentModel, 10, nil)},
			}},
		},
	}
	return json.Marshal(document)
}

func upstreamDocument(identifier, baseURL string) map[string]any {
	return map[string]any{
		"id": identifier, "type": "openai_compatible", "baseUrl": baseURL,
		"authentication": map[string]any{"type": "bearer", "secretRef": "secret/provider-credential"},
		"staticHeaders":  map[string]any{"X-Provider-Tenant": providerTenant},
		"timeouts": map[string]any{
			"connect": "2s", "responseHeader": "5s", "firstByte": "5s", "idle": "2s", "total": "10s",
		},
	}
}

func modelDocument(identifier, upstream string) map[string]any {
	return map[string]any{
		"id": identifier, "upstream": upstream, "upstreamModel": providerModel,
		"pricingRef": pricingID, "inputAccountingRef": inputProfileID,
		"capabilities": []any{protocol.OpenAIChatID},
	}
}

func calendarLimit(metric string, scope []any, window string, maximum int64) map[string]any {
	return map[string]any{
		"metric": metric, "algorithm": quota.CalendarAlgorithm, "scope": scope,
		"window": window, "maximum": maximum, "hard": true,
	}
}

func perRequestLimit(metric string, scope []any, maximum int64) map[string]any {
	return map[string]any{
		"metric": metric, "algorithm": quota.PerRequestAlgorithm, "scope": scope,
		"perRequestMaximum": maximum, "hard": true,
	}
}

func routeDocument(identifier, model string, priority int64, fallback []any) map[string]any {
	route := map[string]any{
		"id": identifier, "when": "true", "model": model, "priority": priority,
	}
	if fallback != nil {
		route["fallbackOn"] = fallback
	}
	return route
}

func featureDocument(identifier, plan string, maximum int64, routes []any) map[string]any {
	return map[string]any{
		"id": identifier, "protocol": protocol.OpenAIChatID, "attestationPolicy": "native",
		"access":    map[string]any{"expression": "principal.authenticated && principal.claims.tier == 'pro'"},
		"limitPlan": map[string]any{"expression": "'" + plan + "'"},
		"output":    map[string]any{"defaultMaximumTokens": maximum, "absoluteMaximumTokens": maximum},
		"routes":    routes,
	}
}

func (f *fixture) activateConfiguration(ctx context.Context) error {
	store, err := configuration.NewStore(f.pool)
	if err != nil {
		return err
	}
	f.configurationStore = store
	var document []byte
	if f.browserOrigin != "" {
		document, err = f.developmentConfigurationDocument()
	} else {
		document, err = f.configurationDocument()
	}
	if err != nil {
		return err
	}
	revision, err := store.CreateRevision(ctx, f.principal, configuration.CreateInput{
		EnvironmentID: f.tenant.environmentID, Document: document,
		Description: "isolated local verification",
	})
	if err != nil {
		return err
	}
	report, err := store.ValidateRevision(ctx, f.principal, revision.ID)
	if err != nil {
		return err
	}
	if !report.Valid {
		return errors.New("local verification configuration did not validate")
	}
	active, err := store.ActivateRevision(ctx, f.principal, revision.ID, revision.ETag)
	if err != nil {
		return err
	}
	if active.ID != revision.ID || active.State != configuration.StateActive {
		return errors.New("local verification configuration did not activate")
	}
	f.quotaRevisionID = revision.ID
	f.quotaRevisionETag = revision.ETag
	return nil
}

func (f *fixture) verifyConfigurationRollback(ctx context.Context) error {
	second, err := f.configurationStore.CreateRevision(ctx, f.principal, configuration.CreateInput{
		EnvironmentID: f.tenant.environmentID, BaseRevisionID: f.quotaRevisionID,
		Description: "local verification rollback candidate",
	})
	if err != nil {
		return err
	}
	report, err := f.configurationStore.ValidateRevision(ctx, f.principal, second.ID)
	if err != nil || !report.Valid {
		return errors.New("rollback candidate did not validate")
	}
	active, err := f.configurationStore.ActivateRevision(ctx, f.principal, second.ID, second.ETag)
	if err != nil {
		return err
	}
	rolledBack, err := f.configurationStore.Rollback(
		ctx, f.principal, f.tenant.environmentID, f.quotaRevisionID, active.ETag,
	)
	if err != nil {
		return err
	}
	if rolledBack.ID != f.quotaRevisionID || rolledBack.State != configuration.StateActive {
		return errors.New("configuration rollback selected the wrong revision")
	}
	current, err := f.configurationStore.GetActiveRevision(ctx, f.principal, f.tenant.environmentID)
	if err != nil || current.ID != f.quotaRevisionID {
		return errors.New("configuration rollback was not durable")
	}
	return nil
}
