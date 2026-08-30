import { useState } from "react";

import { adminRequest, SystemStatusSchema, type SystemStatus } from "../api/admin";
import { problemFromError, type AdminProblem } from "../api/auth";
import { useConsoleSession } from "../api/session";

export function SystemStatusPanel() {
  const session = useConsoleSession();
  const [data, setData] = useState<SystemStatus>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);

  function refresh(): void {
    if (session.data?.mode !== "configured") return;
    setBusy(true);
    setProblem(undefined);
    void adminRequest("/admin/v1/system", SystemStatusSchema)
      .then((response) => setData(response.data))
      .catch((error: unknown) => setProblem(problemFromError(error)))
      .finally(() => setBusy(false));
  }

  return <section className="detail-card" aria-labelledby="system-status-heading">
    <div className="detail-card__heading">
      <div><p className="eyebrow">Authenticated status</p><h2 id="system-status-heading">Build and schema compatibility</h2></div>
      <button className="secondary-action" disabled={busy} onClick={refresh} type="button">{busy ? "Loading…" : "Load system status"}</button>
    </div>
    {problem ? <p className="control-notice control-notice--error" role="alert">{problem.detail}</p> : null}
    {data ? <dl className="system-status-grid">
      <div><dt>Server</dt><dd>{data.server_version}</dd></div><div><dt>Contract</dt><dd>{data.contract_version}</dd></div>
      <div><dt>Protocols</dt><dd>{data.protocol_versions.join(", ")}</dd></div><div><dt>Role</dt><dd>{data.role}</dd></div>
      <div><dt>Database schema</dt><dd>{data.database_schema_version}</dd></div><div><dt>Ready</dt><dd>{data.ready ? "Yes" : "No"}</dd></div>
    </dl> : <p>Sign in and load the canonical Admin API status to inspect build, protocol, role, and schema state.</p>}
  </section>;
}
