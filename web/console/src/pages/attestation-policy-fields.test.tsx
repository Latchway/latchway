import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ApplePolicyFields, PlayTestingField } from "./attestation-policy-fields";

describe("attestation policy controls", () => {
  it("offers independent development Apple environment and multi-distribution selections", () => {
    render(<ApplePolicyFields environmentKind="development" />);
    expect(screen.getByLabelText("Accepted App Attest environment")).toHaveValue("any");
    expect(screen.getByLabelText("Development signing")).toBeChecked();
    expect(screen.getByLabelText("TestFlight")).toBeChecked();
    expect(screen.getByLabelText("App Store")).not.toBeChecked();
    expect(screen.queryByLabelText(/explicitly allow Apple development/)).not.toBeInTheDocument();
  });

  it("resets defaults safely when changing from Development to Production", () => {
    const view = render(<ApplePolicyFields environmentKind="development" />);
    view.rerender(<ApplePolicyFields environmentKind="production" />);
    expect(screen.getByLabelText("Accepted App Attest environment")).toHaveValue("production");
    expect(screen.getByLabelText("Development signing")).not.toBeChecked();
    expect(screen.getByLabelText("App Store")).toBeChecked();
    expect(screen.getByLabelText(/explicitly allow Apple development/)).not.toBeChecked();
  });

  it("never automatically enables Play testing and disables it outside Development", () => {
    const view = render(<PlayTestingField environmentKind="development" />);
    expect(screen.getByRole("checkbox")).not.toBeChecked();
    expect(screen.getByRole("checkbox")).toBeEnabled();
    for (const environmentKind of ["staging", "production"] as const) {
      view.rerender(<PlayTestingField environmentKind={environmentKind} />);
      expect(screen.getByRole("checkbox")).not.toBeChecked();
      expect(screen.getByRole("checkbox")).toBeDisabled();
    }
  });
});
