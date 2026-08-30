package adminapi

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/latchway/latchway/internal/configuration"
	"github.com/latchway/latchway/internal/dataplane"
	"github.com/latchway/latchway/internal/secrets"
)

type scheduledSelfTestSecretBinding struct {
	Reference string
	RecordID  string
	Version   int64
}

type preparedScheduledSelfTest struct {
	Scope          configuration.TenantScope
	RevisionID     string
	Kind           string
	UpstreamID     string
	ModelID        string
	MaxCostNanoUSD int64
	SecretBindings []scheduledSelfTestSecretBinding
}

type scheduledSelfTestService interface {
	Prepare(context.Context, credentialSelfTestInput) (preparedScheduledSelfTest, error)
	RunBound(context.Context, preparedScheduledSelfTest) credentialSelfTestResult
}

type boundCredentialSecretStore interface {
	dataplane.SecretStore
	ActiveBinding(context.Context, secrets.Scope, string) (secrets.Binding, error)
	UseBound(context.Context, secrets.Scope, string, secrets.Binding, func([]byte) error) error
}

type productionScheduledSelfTestService struct {
	configurations selfTestSnapshotLoader
	secrets        boundCredentialSecretStore
	targets        dataplane.TargetFactory
}

func newProductionScheduledSelfTestService(
	configurations selfTestSnapshotLoader,
	secretStore dataplane.SecretStore,
	targets dataplane.TargetFactory,
) (*productionScheduledSelfTestService, error) {
	bound, ok := secretStore.(boundCredentialSecretStore)
	if !ok || isNilSelfTestDependency(configurations) || isNilSelfTestDependency(bound) ||
		isNilSelfTestDependency(targets) {
		return nil, errors.New("scheduled self-test dependency is nil")
	}
	return &productionScheduledSelfTestService{
		configurations: configurations,
		secrets:        bound,
		targets:        targets,
	}, nil
}

func (service *productionScheduledSelfTestService) Prepare(
	ctx context.Context,
	input credentialSelfTestInput,
) (preparedScheduledSelfTest, error) {
	if service == nil || ctx == nil ||
		(input.Kind != "upstream" && input.Kind != "openrouter") ||
		!selfTestIdentifierPattern.MatchString(input.UpstreamID) ||
		!selfTestIdentifierPattern.MatchString(input.ModelID) ||
		input.MaxCostNano < 1 || input.MaxCostNano > maximumSelfTestCostNanoUSD {
		return preparedScheduledSelfTest{}, errOperationalInvalid
	}
	snapshot, err := service.configurations.CredentialSelfTestSnapshot(ctx, input.Scope)
	if err != nil {
		return preparedScheduledSelfTest{}, errOperationalInvalid
	}
	upstream, ok := snapshot.Upstream(input.UpstreamID)
	if !ok {
		return preparedScheduledSelfTest{}, errOperationalInvalid
	}
	model, ok := snapshot.Model(input.ModelID)
	if !ok || model.UpstreamID != upstream.ID {
		return preparedScheduledSelfTest{}, errOperationalInvalid
	}
	protocolID, ok := credentialSelfTestProtocol(model, input.Kind)
	if !ok || (input.Kind == "openrouter" && !validOpenRouterTarget(upstream)) {
		return preparedScheduledSelfTest{}, errOperationalInvalid
	}
	profile, rates, source, err := credentialSelfTestAccounting(snapshot, model, protocolID, time.Now().UTC())
	if err != nil {
		return preparedScheduledSelfTest{}, errOperationalInvalid
	}
	nonStreaming, err := prepareCredentialRequest(ctx, protocolID, model.UpstreamModel, profile, rates, source, false)
	if err != nil {
		return preparedScheduledSelfTest{}, errOperationalInvalid
	}
	streaming, err := prepareCredentialRequest(ctx, protocolID, model.UpstreamModel, profile, rates, source, true)
	if err != nil {
		return preparedScheduledSelfTest{}, errOperationalInvalid
	}
	worstCase, ok := checkedSelfTestAdd(nonStreaming.maximumCostNano, streaming.maximumCostNano)
	if !ok || worstCase > input.MaxCostNano {
		return preparedScheduledSelfTest{}, errOperationalInvalid
	}

	references, err := scheduledSelfTestSecretReferences(upstream.Authentication)
	if err != nil {
		return preparedScheduledSelfTest{}, errOperationalInvalid
	}
	bindings := make([]scheduledSelfTestSecretBinding, 0, len(references))
	secretScope := secrets.Scope{
		OrganizationID: input.Scope.OrganizationID,
		ApplicationID:  input.Scope.ApplicationID,
		EnvironmentID:  input.Scope.EnvironmentID,
	}
	for _, reference := range references {
		binding, bindErr := service.secrets.ActiveBinding(ctx, secretScope, reference)
		if bindErr != nil {
			return preparedScheduledSelfTest{}, errOperationalInvalid
		}
		bindings = append(bindings, scheduledSelfTestSecretBinding{
			Reference: reference,
			RecordID:  binding.RecordID,
			Version:   binding.Version,
		})
	}
	return preparedScheduledSelfTest{
		Scope: input.Scope, RevisionID: snapshot.PolicyRevision(), Kind: input.Kind,
		UpstreamID: input.UpstreamID, ModelID: input.ModelID,
		MaxCostNanoUSD: input.MaxCostNano, SecretBindings: bindings,
	}, nil
}

func (service *productionScheduledSelfTestService) RunBound(
	ctx context.Context,
	prepared preparedScheduledSelfTest,
) credentialSelfTestResult {
	if service == nil || ctx == nil || prepared.RevisionID == "" {
		return failedCredentialSelfTest(nil, "configuration", "The scheduled self-test binding is invalid.")
	}
	boundSecrets := make(map[string]secrets.Binding, len(prepared.SecretBindings))
	for _, binding := range prepared.SecretBindings {
		if binding.Reference == "" || binding.RecordID == "" || binding.Version < 1 {
			return failedCredentialSelfTest(nil, "credential_binding", "The scheduled credential binding is invalid.")
		}
		if _, duplicate := boundSecrets[binding.Reference]; duplicate {
			return failedCredentialSelfTest(nil, "credential_binding", "The scheduled credential binding is invalid.")
		}
		boundSecrets[binding.Reference] = secrets.Binding{RecordID: binding.RecordID, Version: binding.Version}
	}
	runner, err := newProductionCredentialSelfTests(
		boundRevisionSnapshotLoader{next: service.configurations, revisionID: prepared.RevisionID},
		boundScheduledSecretStore{next: service.secrets, bindings: boundSecrets},
		service.targets,
	)
	if err != nil {
		return failedCredentialSelfTest(nil, "runner", "The scheduled self-test runner is unavailable.")
	}
	return runner.Run(ctx, credentialSelfTestInput{
		Scope: prepared.Scope, Kind: prepared.Kind, UpstreamID: prepared.UpstreamID,
		ModelID: prepared.ModelID, MaxCostNano: prepared.MaxCostNanoUSD,
	})
}

type boundRevisionSnapshotLoader struct {
	next       selfTestSnapshotLoader
	revisionID string
}

func (loader boundRevisionSnapshotLoader) CredentialSelfTestSnapshot(
	ctx context.Context,
	scope configuration.TenantScope,
) (credentialSelfTestSnapshot, error) {
	snapshot, err := loader.next.CredentialSelfTestSnapshot(ctx, scope)
	if err != nil || snapshot.PolicyRevision() != loader.revisionID {
		return nil, errors.New("scheduled configuration binding is unavailable")
	}
	return snapshot, nil
}

type boundScheduledSecretStore struct {
	next     boundCredentialSecretStore
	bindings map[string]secrets.Binding
}

func (store boundScheduledSecretStore) Use(
	ctx context.Context,
	scope secrets.Scope,
	reference string,
	consume func([]byte) error,
) error {
	binding, ok := store.bindings[reference]
	if !ok {
		return secrets.ErrUnavailable
	}
	return store.next.UseBound(ctx, scope, reference, binding, consume)
}

func scheduledSelfTestSecretReferences(authentication configuration.UpstreamAuthentication) ([]string, error) {
	var references []string
	switch authentication.Type {
	case "none":
	case "bearer", "header", "basic":
		references = append(references, authentication.SecretRef)
	case "headers":
		for _, header := range authentication.Headers {
			references = append(references, header.SecretRef)
		}
	default:
		return nil, errors.New("unsupported scheduled authentication")
	}
	if len(references) > 8 {
		return nil, errors.New("too many scheduled secret bindings")
	}
	slices.Sort(references)
	for index, reference := range references {
		if reference == "" || (index > 0 && reference == references[index-1]) {
			return nil, errors.New("invalid scheduled secret binding")
		}
	}
	return references, nil
}
