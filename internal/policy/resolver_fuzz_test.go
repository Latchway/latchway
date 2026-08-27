package policy

import (
	"context"
	"testing"

	"github.com/latchway/latchway/internal/configuration"
)

func FuzzResolve(f *testing.F) {
	f.Add("assistant", "premium", true, uint16(1), uint16(9), byte(0))
	f.Add("assistant", "free", true, uint16(10), uint16(1), byte(1))
	f.Add("missing", "blocked", false, uint16(0), uint16(0), byte(2))

	resolver, err := NewResolver()
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, featureID, plan string, authenticated bool, leftWeight, rightWeight uint16, selector byte) {
		snapshot := policySnapshot()
		feature := snapshot.features["assistant"]
		stickyBy := []string{"none", "user", "installation"}[selector%3]
		feature.Routes = []configuration.Route{
			{ID: "left", When: "true", ModelID: "fast", Priority: 1, Weight: int64(leftWeight), StickyBy: stickyBy},
			{ID: "right", When: "true", ModelID: "reasoning", Priority: 1, Weight: int64(rightWeight), StickyBy: stickyBy},
		}
		snapshot.features["assistant"] = feature
		input := policyInput(plan)
		input.Principal["authenticated"] = authenticated

		decision, resolveErr := resolver.Resolve(context.Background(), snapshot, featureID, input)
		if resolveErr != nil {
			return
		}
		if decision.Feature.ID != featureID || decision.LimitPlan.ID == "" || decision.Route.ID == "" || decision.Model.ID == "" || decision.Upstream.ID == "" {
			t.Fatalf("incomplete successful decision: %+v", decision)
		}
		again, secondErr := resolver.Resolve(context.Background(), snapshot, featureID, input)
		if secondErr != nil || again.Route.ID != decision.Route.ID {
			t.Fatalf("deterministic resolve changed: first=%+v second=%+v err=%v", decision, again, secondErr)
		}
	})
}
