package adminapi

import (
	"strings"
	"testing"

	"github.com/latchway/latchway/internal/id"
)

func TestDescribeUserOperationBindsReviewedStateAndCounts(t *testing.T) {
	t.Parallel()
	organizationID := id.Must(id.Organization)
	environmentID := id.Must(id.Environment)
	userID := id.Must(id.ApplicationUser)
	counts := userOperationCounts{
		ActiveSessionGrants: 2, ActiveRefreshTokens: 1,
		ActiveComponentSessions: 1, ActiveComponentRefreshTokens: 1,
		ActiveInstallationFamilies: 1, ActiveClientComponents: 2,
	}
	first := describeUserOperation(userOperationBlock, "active", counts, organizationID, environmentID, userID)
	second := describeUserOperation(userOperationBlock, "active", counts, organizationID, environmentID, userID)
	if !first.Applicable || !first.Immediate || first.Reversible || len(first.ImpactToken) != 43 ||
		first.ImpactToken != second.ImpactToken || !operationalTokenPattern(first.ImpactToken) {
		t.Fatalf("block impact = %+v", first)
	}
	counts.ActiveSessionGrants++
	changedCounts := describeUserOperation(userOperationBlock, "active", counts, organizationID, environmentID, userID)
	changedStatus := describeUserOperation(userOperationBlock, "blocked", counts, organizationID, environmentID, userID)
	if changedCounts.ImpactToken == first.ImpactToken || changedStatus.ImpactToken == first.ImpactToken || changedStatus.Applicable {
		t.Fatalf("impact token failed to bind state/counts: initial=%+v counts=%+v status=%+v", first, changedCounts, changedStatus)
	}
	unblock := describeUserOperation(userOperationUnblock, "blocked", counts, organizationID, environmentID, userID)
	if !unblock.Applicable || !unblock.Reversible || !strings.Contains(unblock.Summary, "without restoring") {
		t.Fatalf("unblock impact = %+v", unblock)
	}
}
