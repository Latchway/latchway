import type { ApplePolicyInput } from "./attestation-policy-input";

export function ApplePolicyFields({ environmentKind }: Pick<ApplePolicyInput, "environmentKind">) {
  const development = environmentKind === "development";
  return <fieldset key={environmentKind}>
    <legend>Apple evidence acceptance</legend>
    <label>Accepted App Attest environment<select defaultValue={development ? "any" : "production"} name="app_attest_environment" required>
      <option value="production">Production</option><option value="development">Development</option><option value="any">Any (development or production)</option>
    </select></label>
    <small>Independent of the Latchway environment. TestFlight uses production App Attest; local development builds normally use development. Any is a server policy, not an Apple entitlement.</small>
    <fieldset><legend>Allowed signing and distribution categories</legend>
      {([[3, "Development signing"], [2, "TestFlight"], [4, "App Store"], [5, "Ad hoc / enterprise"]] as const).map(([category, label]) =>
        <label className="check-field" key={category}><input defaultChecked={development ? category === 2 || category === 3 : category === 4} name="apple_validation_categories" type="checkbox" value={category} />{label}</label>
      )}
    </fieldset>
    <small>These checks apply when Apple supplies signed launch metadata. Older OS evidence may omit distribution and build metadata; absence does not establish a distribution category.</small>
    {environmentKind === "production" ? <label className="check-field"><input name="dangerous_allow_in_production" type="checkbox" />I explicitly allow Apple development attestation in this Production environment. This weakens the distribution boundary and is audited on activation.</label> : null}
  </fieldset>;
}

export function PlayTestingField({ environmentKind }: Pick<ApplePolicyInput, "environmentKind">) {
  return <label className="check-field" key={environmentKind}><input disabled={environmentKind !== "development"} name="allow_play_testing_responses" type="checkbox" />Accept Google Play Console testing responses (Development only). Test responses retain debug trust and still require matching app identity, request binding, and configured verdicts.</label>;
}
