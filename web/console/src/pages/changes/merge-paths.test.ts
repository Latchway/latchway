import { describe, expect, it } from "vitest";

import { promotionPath, valueAtPath } from "./merge-paths";

describe("merge paths", () => {
  const document = { spec: { "a/b": { "c~d": 1 }, features: [{ id: "chat", plan: "free" }, { id: "x/y", plan: "paid" }] } };

  it("reads values by object key and by identified list entry", () => {
    expect(valueAtPath(document, "/spec/features/chat/plan")).toBe("free");
    expect(valueAtPath(document, "/spec/features/x~1y/plan")).toBe("paid");
    expect(valueAtPath(document, "/spec/a~1b/c~0d")).toBe(1);
    expect(valueAtPath(document, "/spec/features/missing")).toBeUndefined();
    expect(valueAtPath(document, "/spec/features/chat/plan/deeper")).toBeUndefined();
    expect(valueAtPath(document, "/")).toBe(document);
    expect(valueAtPath(document, "/spec/toString")).toBeUndefined();
  });

  it("names promotion paths in console terms", () => {
    expect(promotionPath("/metadata")).toBe("Environment name and labels");
    expect(promotionPath("/spec/upstreams/openai")).toBe("AI connections: openai");
    expect(promotionPath("/spec/features")).toBe("features");
  });
});
