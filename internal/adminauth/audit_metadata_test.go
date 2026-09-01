package adminauth

import (
	"context"
	"testing"
)

func TestAuditMetadataIsClosedBoundedAndSystemOwned(t *testing.T) {
	t.Parallel()
	ctx, err := WithAuditMetadata(context.Background(), AuditSourceCLI, "support_case_123")
	if err != nil {
		t.Fatal(err)
	}
	ctx, err = ResolveAuditMetadata(ctx, AuthenticationAPIToken)
	if err != nil {
		t.Fatal(err)
	}
	actor, err := NewAPITokenActor("tok_00000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	metadata := auditMetadataFromContext(ctx, actor)
	if metadata.source != AuditSourceCLI || metadata.reason != "support_case_123" {
		t.Fatalf("metadata = %+v", metadata)
	}
	if system := auditMetadataFromContext(ctx, SystemActor()); system.source != AuditSourceSystem || system.reason != "" {
		t.Fatalf("system metadata = %+v", system)
	}
	for _, reason := range []string{"Support case", "provider_secret", "token_rotation", "x\nreason"} {
		if ValidateAuditReason(reason) == nil {
			t.Errorf("unsafe audit reason accepted: %q", reason)
		}
	}
	if _, err := WithAuditMetadata(context.Background(), AuditSourceSystem, ""); err == nil {
		t.Fatal("external caller selected the system source")
	}
	spoofed, err := WithAuditMetadata(context.Background(), AuditSourceConsole, "planned_change")
	if err != nil {
		t.Fatal(err)
	}
	spoofed, err = ResolveAuditMetadata(spoofed, AuthenticationAPIToken)
	if err != nil {
		t.Fatal(err)
	}
	if metadata := auditMetadataFromContext(spoofed, actor); metadata.source != AuditSourceAPI {
		t.Fatalf("API token spoofed Console source: %+v", metadata)
	}
	session, err := WithAuditMetadata(context.Background(), AuditSourceCLI, "planned_change")
	if err != nil {
		t.Fatal(err)
	}
	session, err = ResolveAuditMetadata(session, AuthenticationSession)
	if err != nil {
		t.Fatal(err)
	}
	adminActor, err := NewAdminUserActor("adm_00000000000000000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if metadata := auditMetadataFromContext(session, adminActor); metadata.source != AuditSourceConsole {
		t.Fatalf("session source was not derived as Console: %+v", metadata)
	}
}
