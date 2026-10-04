import { useState } from "react";

import { Badge, Button, Icon, Input } from "../../ui";
import type { JSONRecord } from "../configuration-slice";
import {
  type Algorithm,
  algorithmOf,
  CLAIM_NAME,
  dollarsToNano,
  isProtection,
  KIND_LABEL,
  limitSentence,
  METRIC_ORDER,
  METRICS,
  nanoToDollars,
  parseWindow,
  SCOPE_DIMENSIONS,
  SCOPE_PRESETS,
  scopePreset,
  strings,
  withKind,
  withMetric
} from "./limit-model";

const UNIT_LABEL: ReadonlyArray<readonly [string, string]> = [["m", "minute"], ["h", "hour"], ["d", "day"], ["w", "week"], ["mo", "month"]];
const REFILL_UNITS: ReadonlyArray<readonly [number, string]> = [[1, "second"], [60, "minute"], [3600, "hour"]];
const TIMEZONES: readonly string[] = (() => {
  try {
    return typeof Intl.supportedValuesOf === "function" ? Intl.supportedValuesOf("timeZone") : ["UTC"];
  } catch {
    return ["UTC"];
  }
})();

/** The limit as one line: the parts that can change are bold. */
export function LimitSentenceText({ limit }: { limit: JSONRecord }) {
  const sentence = limitSentence(limit);
  return (
    <span className="lw-sentence-text">
      {sentence.who ? <><strong>{sentence.who}</strong> </> : null}
      {sentence.verb} <strong>{sentence.amount}</strong>
      {sentence.tail ? (sentence.tail.startsWith(",") ? sentence.tail : ` ${sentence.tail}`) : null}
    </span>
  );
}

function numberOrUndefined(text: string): number | undefined {
  if (!/^\d{1,16}$/.test(text.trim())) return undefined;
  const value = Number(text);
  return Number.isSafeInteger(value) ? value : undefined;
}

function setField(limit: JSONRecord, key: string, value: unknown): JSONRecord {
  const next = { ...limit };
  if (value === undefined) delete next[key];
  else next[key] = value;
  return next;
}

/** Inline controls for one limit: the same sentence as selects and inputs. */
function LimitControls({ index, limit, onChange }: { index: number; limit: JSONRecord; onChange: (limit: JSONRecord) => void }) {
  const metric = String(limit.metric ?? "");
  const kind = algorithmOf(limit);
  const scope = strings(limit.scope);
  const preset = scopePreset(scope);
  const [custom, setCustom] = useState(!preset);
  const [dollars, setDollars] = useState(metric === "cost_nano_usd" && typeof limit.maximum === "number" ? nanoToDollars(limit.maximum).replace("$", "") : "");
  const window = parseWindow(limit.window) ?? { amount: 1, unit: "d" };
  const rate = typeof limit.refillPerSecond === "number" ? limit.refillPerSecond : 1;
  const [refillUnit, setRefillUnit] = useState(REFILL_UNITS.find(([seconds]) => Number.isInteger(Math.round(rate * seconds * 1e6) / 1e6) && rate * seconds >= 1)?.[0] ?? 1);
  const label = (text: string) => `Limit ${index + 1} ${text}`;
  const claim = scope.find((dimension) => dimension.startsWith("normalized_claim:"))?.slice("normalized_claim:".length) ?? "";
  const amountKey = kind === "token_bucket" ? "capacity" : kind === "per_request" ? "perRequestMaximum" : "maximum";

  return (
    <div className="lw-limit__body">
      <div className="lw-sentence">
        {kind !== "per_request" ? (
          <select aria-label={label("counts")} className="lw-select lw-select--sm lw-in--scope" onChange={(event) => {
            if (event.target.value === "custom") { setCustom(true); return; }
            setCustom(false);
            onChange({ ...limit, scope: [...(SCOPE_PRESETS.find((candidate) => candidate.id === event.target.value)?.scope ?? ["user"])] });
          }} value={custom ? "custom" : preset ?? "custom"}>
            {SCOPE_PRESETS.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.label}</option>)}
            <option value="custom">Custom…</option>
          </select>
        ) : <span>No single request</span>}
        <span>{kind === "calendar" ? "can use" : kind === "token_bucket" ? "can burst to" : kind === "concurrency" ? "can have" : kind === "per_request" ? "can use more than" : ""}</span>
        {metric === "cost_nano_usd" ? (
          <Input aria-label={label("amount in dollars")} boxClassName="lw-in--amount" inputMode="decimal" onChange={(event) => { setDollars(event.target.value); onChange(setField(limit, "maximum", dollarsToNano(event.target.value))); }} suffix={<span className="lw-faint lw-note">USD</span>} value={dollars} />
        ) : (
          <Input aria-label={label("amount")} boxClassName="lw-in--amount" inputMode="numeric" onChange={(event) => onChange(setField(limit, amountKey, numberOrUndefined(event.target.value)))} value={limit[amountKey] === undefined ? "" : String(limit[amountKey])} />
        )}
        <select aria-label={label("metric")} className="lw-select lw-select--sm lw-in--metric" onChange={(event) => onChange(withMetric(limit, event.target.value))} value={metric}>
          {!METRICS[metric] ? <option value={metric}>{metric} (not enforceable)</option> : null}
          {METRIC_ORDER.map((value) => <option key={value} value={value}>{value === "cost_nano_usd" ? "dollars of spend" : METRICS[value]?.other}</option>)}
        </select>
        {kind === "calendar" ? (
          <>
            <span>per</span>
            <Input aria-label={label("period length")} boxClassName="lw-in--num" inputMode="numeric" onChange={(event) => onChange({ ...limit, window: `${numberOrUndefined(event.target.value) ?? 0}${window.unit}` })} value={String(window.amount)} />
            <select aria-label={label("period unit")} className="lw-select lw-select--sm lw-in--unit" onChange={(event) => onChange({ ...limit, window: `${window.amount}${event.target.value}` })} value={window.unit}>
              {UNIT_LABEL.map(([unit, name]) => <option key={unit} value={unit}>{window.amount === 1 ? name : `${name}s`}</option>)}
            </select>
          </>
        ) : null}
        {kind === "token_bucket" ? (
          <>
            <span>refilling</span>
            <Input aria-label={label("refill amount")} boxClassName="lw-in--num" inputMode="decimal" onChange={(event) => { const value = Number(event.target.value); onChange(setField(limit, "refillPerSecond", Number.isFinite(value) && value > 0 ? Math.round((value / refillUnit) * 1e6) / 1e6 : undefined)); }} value={String(Math.round(rate * refillUnit * 1e6) / 1e6)} />
            <select aria-label={label("refill unit")} className="lw-select lw-select--sm lw-in--unit" onChange={(event) => setRefillUnit(Number(event.target.value))} value={refillUnit}>
              {REFILL_UNITS.map(([seconds, name]) => <option key={seconds} value={seconds}>per {name}</option>)}
            </select>
          </>
        ) : null}
        {kind === "concurrency" ? <span>at once</span> : null}
      </div>
      {custom && kind !== "per_request" ? (
        <fieldset className="lw-fieldset lw-limit__scope">
          <legend>Who it counts</legend>
          <div className="lw-check-grid">
            {SCOPE_DIMENSIONS.map(([dimension, name]) => (
              <label className="lw-check" key={dimension}>
                <input checked={scope.includes(dimension)} onChange={(event) => onChange({ ...limit, scope: event.target.checked ? [...scope, dimension] : scope.filter((value) => value !== dimension) })} type="checkbox" />
                <span>{name}</span>
              </label>
            ))}
          </div>
          <label className="lw-field__label" htmlFor={`limit-${index}-claim`}>And one claim (optional)</label>
          <Input id={`limit-${index}-claim`} mono onChange={(event) => {
            const name = event.target.value.trim();
            const rest = scope.filter((value) => !value.startsWith("normalized_claim:"));
            onChange({ ...limit, scope: name ? [...rest, `normalized_claim:${name}`] : rest });
          }} placeholder="e.g. team" value={claim} />
          {claim && !CLAIM_NAME.test(claim) ? <span className="lw-field__error">Claim names use lowercase letters, digits and _.</span> : null}
          <span className="lw-field__hint">Each extra dimension splits the counter, so the limit gets looser, not stricter.</span>
        </fieldset>
      ) : null}
      <div className="lw-limit__opts">
        <label className="lw-field">
          <span className="lw-field__label">Kind of limit</span>
          <select aria-label={label("kind")} className="lw-select" onChange={(event) => onChange(withKind(limit, event.target.value as Algorithm))} value={kind ?? ""}>
            {!kind ? <option value="">Choose</option> : null}
            {(METRICS[metric]?.algorithms ?? ["calendar"]).map((value) => <option key={value} value={value}>{KIND_LABEL[value]}</option>)}
          </select>
        </label>
        {kind === "calendar" ? (
          <label className="lw-field">
            <span className="lw-field__label">Periods start in</span>
            <select aria-label={label("time zone")} className="lw-select" onChange={(event) => onChange({ ...limit, timezone: event.target.value })} value={String(limit.timezone ?? "UTC")}>
              {[...new Set(["UTC", String(limit.timezone ?? "UTC"), ...TIMEZONES])].map((zone) => <option key={zone} value={zone}>{zone}</option>)}
            </select>
          </label>
        ) : null}
        {metric === "cost_nano_usd" ? (
          <label className="lw-field">
            <span className="lw-field__label">Retries</span>
            <select aria-label={label("retries")} className="lw-select" onChange={(event) => onChange(setField(limit, "costRetryTreatment", event.target.value === "actual_attempts" ? undefined : event.target.value))} value={String(limit.costRetryTreatment ?? "actual_attempts")}>
              <option value="actual_attempts">Count every attempt</option>
              <option value="initial_attempt_only">First attempt only</option>
            </select>
          </label>
        ) : null}
        <div className="lw-field"><span className="lw-field__label">When it&apos;s reached</span><span className="lw-note">Block the request. Track-only limits can&apos;t be activated by this server.</span></div>
      </div>
      {kind === "calendar" ? <p className="lw-limit__hint">Weeks start Monday. Spend is entered in dollars and stored as exact nano-USD.</p> : null}
    </div>
  );
}

interface LimitCardProps {
  canRemove: boolean;
  editable: boolean;
  index: number;
  limit: JSONRecord;
  onChange: (limit: JSONRecord) => void;
  onRemove: () => void;
  onToggle: () => void;
  open: boolean;
  problems: readonly string[];
}

/** One limit, read as a sentence; it opens in place into the same sentence as controls. */
export function LimitCard({ canRemove, editable, index, limit, onChange, onRemove, onToggle, open, problems }: LimitCardProps) {
  return (
    <li className={`lw-limit${open ? " lw-limit--open" : ""}${problems.length ? " lw-limit--invalid" : ""}`}>
      <div className="lw-limit__head">
        <button aria-expanded={open} className="lw-limit__summary" disabled={!editable} onClick={onToggle} type="button">
          <Icon name={open ? "chevronDown" : "chevronRight"} size={16} />
          <LimitSentenceText limit={limit} />
          <span className="lw-limit__tags">
            {isProtection(limit) ? <Badge color="cyan" variant="soft">Protection</Badge> : null}
            <Badge variant="soft">Blocks</Badge>
          </span>
        </button>
        {editable ? <Button aria-label={`Remove limit ${index + 1}`} disabled={!canRemove} icon="trash" onClick={onRemove} size="sm" title={canRemove ? undefined : "A plan keeps at least one limit"} variant="ghost" /> : null}
      </div>
      {open && editable ? <LimitControls index={index} limit={limit} onChange={onChange} /> : null}
      {problems.length ? <div className="lw-limit__body"><div className="lw-limit__errors">{problems.map((problem) => <span key={problem}>{problem}</span>)}</div></div> : null}
    </li>
  );
}
