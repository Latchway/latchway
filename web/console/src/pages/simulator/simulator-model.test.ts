import { beforeEach, describe, expect, it, vi } from "vitest";

const { adminRequestMock } = vi.hoisted(() => ({ adminRequestMock: vi.fn() }));
vi.mock("../../api/admin", async (importOriginal) => ({ ...(await importOriginal<typeof import("../../api/admin")>()), adminRequest: adminRequestMock }));

import { simulationFixture } from "./simulator-fixture";
import { changedStages, cliCommand, deniedAt, handlingStep, outcomeText, simulate, type SimulationInput, SIZE_PRESETS, whatIfVariants } from "./simulator-model";


const input: SimulationInput = { authenticated: true, claims: { plan: "free" }, feature: "assistant", platform: "ios", size: SIZE_PRESETS[0]!.size, streaming: false, trustLevel: "app_verified" };

beforeEach(() => {
  adminRequestMock.mockReset();
});

describe("simulator model", () => {
  it("maps each server denial sentence to the stage that stopped the request", () => {
    const denied = (sentence: string) => simulationFixture({ allowed: false, explanation: [sentence] });
    expect(deniedAt(denied("Authentication fails before production policy evaluation."))).toBe("signed_in");
    expect(deniedAt(denied("The feature's attestation policy does not define the simulated platform."))).toBe("app_verified");
    expect(deniedAt(denied("The compiled access expression denied the simulated principal."))).toBe("access");
    expect(deniedAt(denied("The compiled limit-plan expression selected no executable plan."))).toBe("plan");
    expect(deniedAt(denied("No executable route matched the simulated facts."))).toBe("route");
    expect(deniedAt(denied("Something new."))).toBeUndefined();
    expect(outcomeText(denied("The compiled access expression denied the simulated principal."))).toBe("Denied at Feature access");
    expect(outcomeText(simulationFixture())).toBe("Allowed · free · fast on openai");
  });

  it("marks changed stages and computes pretend-down from the fallback sequence", () => {
    const before = simulationFixture();
    const after = simulationFixture({ limit_plan: "premium", model: "slow" });
    expect([...changedStages(before, after)]).toEqual(["plan"]);
    expect(handlingStep(before, new Set(["openai"]))).toBe(1);
    expect(handlingStep(before, new Set(["openai", "anthropic"]))).toBeUndefined();
  });

  it("offers one-change What if variants", () => {
    const labels = whatIfVariants(input, ["free", "premium"]).map((variant) => variant.label);
    expect(labels).toEqual(["Plan claim is premium", "From the web", "From Android", "Trust one level lower (Web risk check)", "Streaming", "A 4× longer prompt", "Signed out"]);
  });

  it("writes claims to a file through a heredoc, never into command flags", () => {
    const command = cliCommand("rev_0123456789abcdef", { ...input, claims: { plan: "premium" } });
    expect(command.split("\n")[0]).toBe("cat > claims.json <<'EOF'");
    expect(command).toContain("latchway routes simulate rev_0123456789abcdef \\");
    expect(command).toContain("--claims-file claims.json");
    expect(command.split("latchway routes simulate")[1]).not.toContain("premium");
  });

  it("rejects a result for another revision or feature", async () => {
    adminRequestMock.mockResolvedValueOnce({ data: simulationFixture({ revision_id: "rev_9999999999999999" }) });
    await expect(simulate("rev_0123456789abcdef", input)).rejects.toThrow(/didn't match/);
    adminRequestMock.mockResolvedValueOnce({ data: simulationFixture() });
    await expect(simulate("rev_0123456789abcdef", input)).resolves.toMatchObject({ allowed: true });
    expect(adminRequestMock.mock.calls[1]?.[2]).toMatchObject({ body: { feature: "assistant", platform: "ios", principal: { authenticated: true, claims: { plan: "free" } }, trust_level: "app_verified" }, method: "POST" });
  });
});
