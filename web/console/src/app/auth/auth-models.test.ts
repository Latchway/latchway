import { describe, expect, it } from "vitest";

import { acceptable, passwordStrength } from "./password-strength";
import { slugify, validateSetup } from "./setup-model";

describe("passwordStrength", () => {
  it.each([
    ["short1!A", "too-short"],
    ["aaaaaaaaaaaaaaaaaaaaaaaa", "weak"],
    ["abcdefghijkl", "weak"],
    ["abcdefGH1jkl", "good"],
    ["correct horse battery", "strong"],
    ["Abcdef1!ghijklmn", "strong"]
  ])("rates %s as %s", (password, strength) => {
    expect(passwordStrength(password)).toBe(strength);
  });

  it("accepts only good or strong", () => {
    expect(acceptable("good")).toBe(true);
    expect(acceptable("strong")).toBe(true);
    expect(acceptable("weak")).toBe(false);
    expect(acceptable("too-short")).toBe(false);
  });
});

describe("setup model", () => {
  it("suggests slugs the server accepts", () => {
    expect(slugify("Acme Corp")).toBe("acme-corp");
    expect(slugify("42 Café Ünits!")).toBe("cafe-units");
    expect(slugify("x".repeat(80))).toHaveLength(63);
  });

  it("reports every problem at once", () => {
    const problems = validateSetup({ bootstrap_token: "short", display_name: " ", email: "nope", organization_name: "", organization_slug: "9bad", password: "aaaaaaaaaaaa" });
    expect(Object.keys(problems).sort()).toEqual(["bootstrap_token", "display_name", "email", "organization_name", "organization_slug", "password"]);
  });

  it("passes a complete setup", () => {
    expect(validateSetup({ bootstrap_token: "t".repeat(32), display_name: "Owner", email: "owner@example.test", organization_name: "Acme", organization_slug: "acme", password: "test-only-owner-password" })).toEqual({});
  });
});
