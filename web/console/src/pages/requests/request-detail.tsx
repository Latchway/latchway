import { Link } from "@tanstack/react-router";
import { type ReactNode, useEffect, useRef, useState } from "react";

import type { EffectiveConfiguration, LogicalRequest } from "../../api/admin";
import type { AdminProblem } from "../../api/auth";
import { Button, DetailPanel, Icon, Properties, StatusBadge } from "../../ui";
import { displayUsageMetric } from "../usage-display";
import {
  ATTEMPT_FAILURE_TEXT,
  capitalize,
  elapsedMs,
  errorDocumentationURL,
  formatClock,
  formatMs,
  formatUsd,
  formatUtc,
  outcomeSentence,
  outcomeStatus,
  PLATFORM_LABEL,
  PROVIDER_ERROR_TEXT,
  requestDuration,
  STAGE_LABEL,
  stageDetail,
  timeToFirstToken,
  TRUST_LABEL,
  words
} from "./request-format";
import type { RequestFilters } from "./request-query";

type Attempt = LogicalRequest["attempts"][number];

export interface WorkspaceLinkSearch {
  application?: string;
  environment?: string;
  organization?: string;
}

function copyText(text: string): Promise<void> {
  try {
    return navigator.clipboard ? navigator.clipboard.writeText(text) : Promise.reject(new Error("clipboard unavailable"));
  } catch (error) {
    return Promise.reject(error);
  }
}

/** A copy button that reports what happened in place, since the console has no toast queue. */
export function CopyButton({ className = "lw-idbtn", label, value, children }: { children?: ReactNode; className?: string; label: string; value: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return (
    <button
      aria-label={state === "copied" ? `${label} copied` : state === "failed" ? `${label}: copying isn't available here` : label}
      className={className}
      onClick={() => {
        copyText(value).then(() => setState("copied"), () => setState("failed"));
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => setState("idle"), 1_600);
      }}
      title={label}
      type="button"
    >
      {children ?? <Icon name={state === "copied" ? "check" : "copy"} />}
      {state === "copied" ? <span className="lw-sr" role="status">Copied</span> : null}
    </button>
  );
}

function Faint({ children }: { children: ReactNode }) {
  return <span className="lw-faint">{children}</span>;
}

function Mono({ children }: { children: ReactNode }) {
  return <span className="lw-mono lw-mono--sm">{children}</span>;
}

/** Decision stages and attempts on one time scale, from the request's start. */
export function RequestWaterfall({ request }: { request: LogicalRequest }) {
  const total = requestDuration(request) ?? Math.max(0, ...request.attempts.map((attempt) => elapsedMs(request.started_at, attempt.completed_at) ?? 0));
  const scale = Math.max(total, 1);
  const pct = (ms: number) => Math.max(0, Math.min(100, (ms / scale) * 100));
  const lastStage = request.decision_stages.at(-1);
  const stagesEnd = lastStage ? elapsedMs(request.started_at, lastStage.completed_at) ?? 0 : 0;
  const denied = request.decision_stages.some((stage) => stage.outcome !== "succeeded");
  return (
    <div aria-label={`Timeline: ${request.decision_stages.length} decision stages in ${formatMs(stagesEnd)}, then ${request.attempts.length} attempt${request.attempts.length === 1 ? "" : "s"}, ${formatMs(total)} in total`} className="lw-wf" role="img">
      <div className="lw-wf__row">
        <span className="lw-wf__label">Decision</span>
        <span className="lw-wf__track"><span className={`lw-wf__bar is-stages${denied ? " is-deny" : ""}`} style={{ left: 0, width: `${Math.max(pct(stagesEnd), 0.8)}%` }} /></span>
        <span className="lw-wf__ms">{formatMs(stagesEnd)}</span>
      </div>
      {request.attempts.map((attempt) => {
        const start = elapsedMs(request.started_at, attempt.started_at) ?? 0;
        const end = elapsedMs(request.started_at, attempt.completed_at ?? request.completed_at) ?? start;
        const byte = attempt.first_byte_at ? elapsedMs(request.started_at, attempt.first_byte_at) : undefined;
        const token = attempt.first_token_at ? elapsedMs(request.started_at, attempt.first_token_at) : undefined;
        return (
          <div className="lw-wf__row" key={attempt.id}>
            <span className="lw-wf__label">Attempt {attempt.attempt_number}</span>
            <span className="lw-wf__track">
              <span className={`lw-wf__bar is-${attempt.status}`} style={{ left: `${pct(start)}%`, width: `${Math.max(pct(end - start), 0.8)}%` }} />
              {byte !== undefined ? <span className="lw-wf__mark is-byte" style={{ left: `${pct(byte)}%` }} title={`First byte at ${formatMs(byte)}`} /> : null}
              {token !== undefined ? <span className="lw-wf__mark is-token" style={{ left: `${pct(token)}%` }} title={`First token at ${formatMs(token)}`} /> : null}
            </span>
            <span className="lw-wf__ms">{formatMs(end - start)}</span>
          </div>
        );
      })}
      <div className="lw-wf__legend">
        <span><i className="is-byte" />First byte</span>
        <span><i className="is-token" />First token</span>
        <span><i className="is-failed" />Failed attempt</span>
        <span className="lw-wf__total">0 → {formatMs(total)}</span>
      </div>
    </div>
  );
}

function provenanceWords(value: string): string {
  return value === "upstream_reported" ? "reported by the provider" : value === "calculated" ? "calculated from your prices" : value === "configured" ? "configured" : value === "estimated" ? "estimated" : "provenance unknown";
}

function AttemptCard({ attempt }: { attempt: Attempt }) {
  const [showAccounting, setShowAccounting] = useState(false);
  const duration = elapsedMs(attempt.started_at, attempt.completed_at);
  const firstByte = attempt.first_byte_at ? elapsedMs(attempt.started_at, attempt.first_byte_at) : undefined;
  const firstToken = attempt.first_token_at ? elapsedMs(attempt.started_at, attempt.first_token_at) : undefined;
  const error = attempt.provider_error;
  const breakdown = attempt.input_accounting_breakdown;
  return (
    <div className={`lw-attempt is-${attempt.status}`}>
      <div className="lw-attempt__head">
        <strong>Attempt {attempt.attempt_number}{attempt.attempt_number > 1 ? " · fallback" : ""}</strong>
        <span className="lw-mono">{attempt.upstream} · {attempt.model || "—"} · route {attempt.route}</span>
        <StatusBadge status={attempt.status === "succeeded" ? "succeeded" : attempt.status === "canceled" ? "canceled" : attempt.status === "unknown" ? "running" : "failed"}>
          {attempt.status === "succeeded" ? "Succeeded" : attempt.status === "unknown" ? "In progress" : ATTEMPT_FAILURE_TEXT[attempt.failure_code ?? "unknown"] ?? capitalize(attempt.status)}
        </StatusBadge>
      </div>
      <Properties columns={2} items={[
        { label: "HTTP status", value: attempt.http_status ? String(attempt.http_status) : <Faint>No response</Faint> },
        { label: "Timing", value: `${formatMs(duration)}${firstByte !== undefined ? ` · first byte ${formatMs(firstByte)}` : ""}${firstToken !== undefined ? ` · first token ${formatMs(firstToken)}` : ""}` },
        { label: "Tokens", value: <span>{displayUsageMetric(attempt.usage, "total_tokens")}<Faint> · {provenanceWords(attempt.usage_provenance)}</Faint></span> },
        { label: "Cost", value: <span>{displayUsageMetric(attempt.usage, "cost_nano_usd")}<Faint> · {provenanceWords(attempt.cost_provenance)}{attempt.cost_source ? ` · ${attempt.cost_source}` : ""}</Faint></span> },
        ...(attempt.failure_code ? [{ label: "Failure", value: <a href={errorDocumentationURL(attempt.failure_code)} rel="noreferrer" target="_blank">{attempt.failure_code}</a> }] : []),
        ...(attempt.accounting_policy ? [{ label: "Accounting", value: words(attempt.accounting_policy) }] : [])
      ]} />
      {error ? (
        <div className="lw-attempt__perr">
          <strong>{words(error.category ?? "provider error")}</strong>
          <span>{error.category ? PROVIDER_ERROR_TEXT[error.category] : "The provider returned an error."}{error.parameter ? ` Parameter: ${error.parameter}.` : ""}{error.provider_code ? ` Provider code: ${error.provider_code}.` : ""}</span>
          {error.request_id || error.generation_id ? (
            <span className="lw-attempt__ids">
              {error.request_id ? <CopyButton label={`Copy provider request ID ${error.request_id}`} value={error.request_id}>Provider request <code>{error.request_id}</code></CopyButton> : null}
              {error.generation_id ? <CopyButton label={`Copy generation ID ${error.generation_id}`} value={error.generation_id}>Generation <code>{error.generation_id}</code></CopyButton> : null}
            </span>
          ) : null}
          <span className="lw-faint">Give these IDs to the provider's support. Latchway never stores their error text.</span>
        </div>
      ) : null}
      {breakdown ? (
        <div className="lw-attempt__acc">
          <button aria-expanded={showAccounting} className="lw-link" onClick={() => setShowAccounting(!showAccounting)} type="button">
            {showAccounting ? "Hide how the token reservation was calculated" : "How the token reservation was calculated"}
          </button>
          {showAccounting ? (
            <div className="lw-attempt__accbody">
              <p className="lw-secondary lw-note">Before sending, Latchway reserves a conservative input bound from sizes alone. It explains the reservation, not the provider's measured token count.</p>
              <Properties columns={2} items={[
                { label: "Rewritten request", value: `${breakdown.rewritten_request_bytes.toLocaleString()} bytes` },
                { label: "Framing", value: `${breakdown.framing_unit_count} units × up to ${breakdown.maximum_framing_tokens_per_unit} tokens, + ${breakdown.maximum_framing_tokens_per_request} per request` },
                { label: "Expanded tool schema", value: `${breakdown.expanded_schema_bytes.toLocaleString()} bytes` },
                { label: "Version", value: `v${breakdown.version}` }
              ]} />
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

interface RequestDetailProps {
  effective?: EffectiveConfiguration;
  explainBusy: boolean;
  onClose: () => void;
  onExplain: () => void;
  onFilter: (filters: RequestFilters) => void;
  renderEffective: (configuration: EffectiveConfiguration) => ReactNode;
  explainProblem?: AdminProblem;
  renderProblem: (problem?: AdminProblem) => ReactNode;
  request: LogicalRequest;
  workspaceSearch: WorkspaceLinkSearch;
}

/** Everything the server recorded about one request. Nothing here is reconstructed from current configuration. */
export function RequestDetail({ effective, explainBusy, explainProblem, onClose, onExplain, onFilter, renderEffective, renderProblem, request, workspaceSearch }: RequestDetailProps) {
  const [now] = useState(() => Date.now());
  const duration = requestDuration(request);
  const ttft = timeToFirstToken(request);
  const legacy = request.decision_stages.length === 0;
  const lastUpstream = request.attempts.at(-1)?.upstream ?? request.selected_upstream;
  const client = [
    request.component_kind ? words(request.component_kind) : undefined,
    request.caller_sdk ? `${request.caller_sdk} SDK` : undefined,
    request.framework ? `${request.framework}${request.framework_version ? ` ${request.framework_version}` : ""}` : undefined
  ].filter(Boolean).join(" · ");
  const environmentID = request.environment_id;

  return (
    <DetailPanel
      actions={<>
        <CopyButton className="lw-btn lw-btn--ghost lw-btn--icon" label="Copy link" value={window.location.href}><Icon name="external" /></CopyButton>
        <CopyButton className="lw-btn lw-btn--ghost lw-btn--icon" label="Copy request ID" value={request.id}><Icon name="copy" /></CopyButton>
      </>}
      className="lw-request-drawer"
      mono
      onClose={onClose}
      sections={[
        {
          content: <>
            <p className="lw-rq-outcome">
              {outcomeSentence(request)}
              {request.failure_code ? <> <a href={errorDocumentationURL(request.failure_code)} rel="noreferrer" target="_blank">About {request.failure_code}</a></> : null}
            </p>
            <div className="lw-rq-jump">
              {request.failure_code ? <Button onClick={() => onFilter({ error_code: request.failure_code })} size="sm">Same error</Button> : null}
              <Button onClick={() => onFilter({ user_id: request.user_id })} size="sm">This user's requests</Button>
              {lastUpstream ? <Button onClick={() => onFilter({ upstream: lastUpstream })} size="sm">Requests through {lastUpstream}</Button> : null}
            </div>
          </>
        },
        {
          content: <Properties columns={2} items={[
            { label: "User", value: <Link className="lw-link lw-mono lw-mono--sm" search={{ ...workspaceSearch, environment_id: environmentID, user_id: request.user_id }} to="/users">{request.user_id}</Link> },
            { label: "Installation family", value: request.installation_family_id ? <Link className="lw-link lw-mono lw-mono--sm" search={{ ...workspaceSearch, environment_id: environmentID, family_id: request.installation_family_id }} to="/installation-families">{request.installation_family_id}</Link> : <Faint>Not recorded (older request)</Faint> },
            { label: "Installation", value: <Mono>{request.installation_id}{request.platform ? <Faint> · {PLATFORM_LABEL[request.platform] ?? words(request.platform)}</Faint> : null}</Mono> },
            ...(request.client_request_id ? [{ label: "Client request ID", value: <span className="lw-rq-clientid"><Mono>{request.client_request_id}</Mono><CopyButton label="Copy client request ID" value={request.client_request_id} /></span> }] : []),
            { label: "Client", value: client || <Faint>Not recorded (older request)</Faint> },
            { label: "Trust", value: request.trust_source ? TRUST_LABEL[request.trust_source] ?? words(request.trust_source) : <Faint>Not recorded (older request)</Faint> },
            { label: "Component", value: request.client_component_id ? <Mono>{request.client_component_id}{request.component_definition_id ? ` · ${request.component_definition_id}` : ""}</Mono> : <Faint>Not recorded (older request)</Faint> },
            { label: "Plan", value: request.selected_limit_plan },
            { label: "Revision", value: <Link className="lw-link lw-mono lw-mono--sm" search={workspaceSearch} to="/configuration-revisions">{request.config_revision_id}</Link> },
            { label: "Route", value: request.selected_route ? <Mono>{request.selected_route} → {request.selected_model} on {request.selected_upstream}{request.selected_physical_model ? ` (${request.selected_physical_model})` : ""}</Mono> : <Faint>Not reached</Faint> },
            { label: "Time", value: <span title={formatUtc(request.started_at)}>{formatClock(request.started_at, now)}{ttft !== undefined ? ` · first token ${formatMs(ttft)}` : ""}</span> },
            { label: "Protocol", value: words(request.protocol) }
          ]} />,
          title: "Summary"
        },
        {
          content: legacy
            ? <p className="lw-secondary lw-note">Recorded before decision stages were kept ({request.config_revision_id}). Only the outcome, route and usage are available; the console doesn't reconstruct the rest from current configuration.</p>
            : <RequestWaterfall request={request} />,
          title: "Timeline"
        },
        ...(legacy ? [] : [{
          content: (
            <ol className="lw-stages">
              {request.decision_stages.map((stage) => {
                const detail = stage.stage === "client_trust_verified" && request.trust_source ? TRUST_LABEL[request.trust_source] : stageDetail(stage);
                return (
                  <li className={`is-${stage.outcome}`} key={stage.number}>
                    <span className="lw-stages__n">{stage.number}</span>
                    <span className="lw-stages__text">
                      <strong>{STAGE_LABEL[stage.stage]}</strong>
                      {detail ? <span>{detail}</span> : null}
                      {stage.failure_code ? <span className="lw-stages__code"><a href={errorDocumentationURL(stage.failure_code)} rel="noreferrer" target="_blank">{stage.failure_code}</a></span> : null}
                    </span>
                    <span className="lw-stages__ms">{stage.duration_ms.toLocaleString()} ms</span>
                  </li>
                );
              })}
            </ol>
          ),
          title: "Decision stages"
        }]),
        ...(request.attempts.length ? [{
          content: <div className="lw-attempts">{request.attempts.map((attempt) => <AttemptCard attempt={attempt} key={attempt.id} />)}</div>,
          title: `Attempts (${request.attempts.length})`
        }] : []),
        {
          content: <>
            <Properties columns={2} items={[
              { label: "Input tokens", value: displayUsageMetric(request.usage, "input_tokens") },
              { label: "Output tokens", value: displayUsageMetric(request.usage, "output_tokens") },
              { label: "Total tokens", value: displayUsageMetric(request.usage, "total_tokens") },
              { label: "Cost", value: request.usage?.details?.cost_nano_usd?.recorded_units != null ? <span title={displayUsageMetric(request.usage, "cost_nano_usd")}>{formatUsd(request.usage.details.cost_nano_usd.recorded_units)} <Faint>({displayUsageMetric(request.usage, "cost_nano_usd")})</Faint></span> : displayUsageMetric(request.usage, "cost_nano_usd") },
              { label: "Counted as", value: `${request.usage?.logical_requests ?? 1} logical request${(request.usage?.logical_requests ?? 1) === 1 ? "" : "s"}, ${request.attempts.length} attempt${request.attempts.length === 1 ? "" : "s"}` }
            ]} />
            <p className="lw-secondary lw-note">Recorded ledger units are not necessarily generated tokens or a provider bill. Unknown usage can carry conservative quota charges; missing cost is not a zero bill.</p>
          </>,
          title: "Usage"
        },
        {
          content: <>
            <p className="lw-secondary lw-note">See the configuration this request ran under: the revision that was live then and the decision provenance it recorded.</p>
            <div><Button icon="simulator" loading={explainBusy} onClick={onExplain} size="sm">Explain This Request</Button></div>
            {renderProblem(explainProblem)}
            {effective ? renderEffective(effective) : null}
          </>,
          title: "Recorded configuration"
        },
        {
          content: <p className="lw-secondary lw-note">Prompts, responses, identity tokens, DPoP proofs and provider error text are never stored. Failure categories are a closed, sanitized vocabulary.</p>,
          title: "Not recorded"
        }
      ]}
      subtitle={<>
        <StatusBadge status={outcomeStatus(request.status)}>{capitalize(request.status)}{request.failure_code ? ` · ${request.failure_code}` : ""}</StatusBadge>
        <span>{request.feature} · {formatClock(request.started_at, now)} · {formatMs(duration)}</span>
      </>}
      title={request.id}
    />
  );
}

