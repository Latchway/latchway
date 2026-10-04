import { useState } from "react";

import { Button, Field, Icon, Input, Notice, Segmented } from "../../ui";
import {
  ATTRIBUTE_LABEL,
  compileRules,
  COMPONENT_KINDS,
  parseRules,
  PLATFORMS,
  type PlanRule,
  type PlanRules,
  type RuleAttribute,
  rulesProblems,
  TRUST_LEVELS
} from "./plan-rules";

export interface PlanSelection {
  expression: string;
  problems: string[];
}

function choices(attribute: RuleAttribute): readonly string[] | undefined {
  if (attribute === "platform") return PLATFORMS;
  if (attribute === "trust_level") return TRUST_LEVELS;
  if (attribute === "component_kind") return COMPONENT_KINDS;
  if (attribute === "streaming") return ["true", "false"];
  return undefined;
}

function defaultValue(attribute: RuleAttribute): string {
  return choices(attribute)?.[0] ?? (attribute === "input_tokens" ? "8000" : "");
}

/**
 * Edits which plan a feature selects, as ordered rules or as raw CEL. The parent receives the compiled expression and
 * any problems with every change; it saves nothing itself.
 */
export function PlanRulesEditor({ expression, idPrefix, onChange, plans }: { expression: string; idPrefix: string; onChange: (selection: PlanSelection) => void; plans: readonly string[] }) {
  const parsed = parseRules(expression);
  const [mode, setMode] = useState<"rules" | "cel">(parsed || !expression ? "rules" : "cel");
  const [rules, setRules] = useState<PlanRules>(parsed ?? { fallback: plans[0] ?? "", rules: [] });
  const [cel, setCel] = useState(expression);

  function emitRules(next: PlanRules): void {
    setRules(next);
    onChange({ expression: compileRules(next), problems: rulesProblems(next, plans) });
  }

  function emitCel(next: string): void {
    setCel(next);
    onChange({ expression: next.trim(), problems: next.trim() ? [] : ["Write the plan rule, or switch back to rules."] });
  }

  function update(index: number, change: Partial<PlanRule>): void {
    emitRules({ ...rules, rules: rules.rules.map((rule, position) => (position === index ? { ...rule, ...change } : rule)) });
  }

  function move(index: number, direction: -1 | 1): void {
    const next = [...rules.rules];
    const [rule] = next.splice(index, 1);
    if (!rule) return;
    next.splice(index + direction, 0, rule);
    emitRules({ ...rules, rules: next });
  }

  function switchMode(next: "rules" | "cel"): void {
    if (next === "cel") {
      setMode("cel");
      emitCel(compileRules(rules));
      return;
    }
    const fromCel = parseRules(cel);
    if (!fromCel && cel.trim()) return;
    setMode("rules");
    emitRules(fromCel ?? rules);
  }

  const planOptions = (value: string) => (
    <>
      {!plans.includes(value) && value ? <option value={value}>{value} (not in the draft)</option> : null}
      {!value ? <option value="">Choose a plan</option> : null}
      {plans.map((plan) => <option key={plan} value={plan}>{plan}</option>)}
    </>
  );
  const celReadable = mode === "cel" && Boolean(parseRules(cel) || !cel.trim());
  const compiled = mode === "rules" ? compileRules(rules) : cel;
  const problems = mode === "rules" ? rulesProblems(rules, plans) : [];

  return (
    <div className="lw-stack lw-stack--tight">
      <Segmented items={[{ id: "rules", label: "Rules" }, { id: "cel", label: "Edit as CEL" }]} label="Plan selection editor" onChange={switchMode} value={mode} />
      {mode === "rules" ? (
        <>
          <ol className="lw-plan-rules">
            {rules.rules.map((rule, index) => {
              const values = choices(rule.attribute);
              return (
                <li className="lw-plan-rule" key={index}>
                  <span className="lw-plan-rule__if">{index ? "Else if" : "If"}</span>
                  <select aria-label={`Rule ${index + 1} attribute`} className="lw-select" onChange={(event) => { const attribute = event.target.value as RuleAttribute; update(index, { attribute, claim: attribute === "claim" ? rule.claim ?? "plan" : undefined, value: defaultValue(attribute) }); }} value={rule.attribute}>
                    {(Object.keys(ATTRIBUTE_LABEL) as RuleAttribute[]).map((attribute) => <option key={attribute} value={attribute}>{ATTRIBUTE_LABEL[attribute]}</option>)}
                  </select>
                  {rule.attribute === "claim" ? <Input aria-label={`Rule ${index + 1} claim name`} mono onChange={(event) => update(index, { claim: event.target.value })} value={rule.claim ?? ""} /> : <span className="lw-faint lw-note">{rule.attribute === "input_tokens" || rule.attribute === "streaming" ? "" : "is"}</span>}
                  {values ? (
                    <select aria-label={`Rule ${index + 1} value`} className="lw-select" onChange={(event) => update(index, { value: event.target.value })} value={rule.value}>
                      {values.map((value) => <option key={value} value={value}>{rule.attribute === "streaming" ? (value === "true" ? "on" : "off") : value.replaceAll("_", " ")}</option>)}
                    </select>
                  ) : <Input aria-label={`Rule ${index + 1} value`} mono onChange={(event) => update(index, { value: event.target.value })} value={rule.value} />}
                  <Icon name="arrowRight" size={14} />
                  <select aria-label={`Rule ${index + 1} plan`} className="lw-select" onChange={(event) => update(index, { plan: event.target.value })} value={rule.plan}>{planOptions(rule.plan)}</select>
                  <span aria-hidden="true" className="lw-plan-rule__share" />
                  <span className="lw-plan-rule__btns">
                    <Button aria-label={`Move rule ${index + 1} up`} disabled={index === 0} icon="arrowUp" onClick={() => move(index, -1)} size="sm" variant="ghost" />
                    <Button aria-label={`Move rule ${index + 1} down`} disabled={index === rules.rules.length - 1} icon="arrowDown" onClick={() => move(index, 1)} size="sm" variant="ghost" />
                    <Button aria-label={`Remove rule ${index + 1}`} icon="trash" onClick={() => emitRules({ ...rules, rules: rules.rules.filter((_, position) => position !== index) })} size="sm" variant="ghost" />
                  </span>
                </li>
              );
            })}
            <li className="lw-plan-rule lw-plan-rule--else">
              <span className="lw-plan-rule__if">{rules.rules.length ? "Everyone else" : "Everyone"}</span>
              <Icon name="arrowRight" size={14} />
              <select aria-label="Plan for everyone else" className="lw-select" onChange={(event) => emitRules({ ...rules, fallback: event.target.value })} value={rules.fallback}>{planOptions(rules.fallback)}</select>
            </li>
          </ol>
          <div><Button icon="plus" onClick={() => emitRules({ ...rules, rules: [...rules.rules, { attribute: "claim", claim: "plan", plan: plans[0] ?? "", value: "" }] })} size="sm">Add Rule</Button></div>
        </>
      ) : (
        <Field hint="Must return a plan ID, e.g. principal.claims.plan == 'premium' ? 'premium' : 'free'. The server validates it." id={`${idPrefix}-cel`} label="Plan rule (CEL)">
          <textarea className="lw-json-editor lw-json-editor--short" id={`${idPrefix}-cel`} maxLength={4096} onChange={(event) => emitCel(event.target.value)} rows={3} spellCheck={false} value={cel} />
        </Field>
      )}
      {mode === "cel" && !celReadable ? <p className="lw-secondary lw-note">This expression can't be shown as rules; it is kept exactly as written.</p> : null}
      {problems.length ? <Notice title="Fix before saving" tone="danger"><ul className="lw-issue-list">{problems.map((problem) => <li key={problem}>{problem}</li>)}</ul></Notice> : null}
      {mode === "rules" ? <p className="lw-secondary lw-note">Compiles to <code className="lw-code-inline">{compiled}</code></p> : null}
      <p className="lw-secondary lw-note">A user's plan override, set under Overrides, wins over these rules.</p>
    </div>
  );
}
