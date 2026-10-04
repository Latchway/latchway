import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { useState } from "react";

import { adminRequest, type Installation, InstallationPageSchema, InstallationSchema, queryPath } from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { useConsoleSession } from "../../api/session";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import { InstallationRouteSearchSchema } from "../../app/route-search";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useWorkspace } from "../../app/workspace-context-value";
import { Badge, Button, type Column, DataTable, DetailPanel, EmptyState, ImpactDialog, Notice, PageHeader, Properties, StatusBadge, Toolbar } from "../../ui";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import { capitalize, formatClock, formatUtc, PLATFORM_LABEL, shortId, words } from "../requests/request-format";
import { GoToForm } from "./go-to-form";

class InstallationContextMismatch extends Error {}

const MISMATCH: AdminProblem = { code: "invalid_response", detail: "The installation list or detail did not match the selected environment and installation ID.", retryable: true, status: 0, title: "Installation context mismatch" };

function RevokeReview({ environmentID, installation, onClose, onDone }: { environmentID: string; installation: Installation; onClose: () => void; onDone: (installation: Installation) => void }) {
  const [pending, setPending] = useState(false);
  const [problem, setProblem] = useState<AdminProblem>();
  async function confirm(reason: string): Promise<void> {
    setPending(true);
    setProblem(undefined);
    try {
      const result = await adminRequest(`/admin/v1/installations/${installation.id}/revoke`, InstallationSchema, { body: { reason }, method: "POST" });
      if (result.data.id !== installation.id || result.data.environment_id !== environmentID) throw new InstallationContextMismatch("installation_context");
      onDone(result.data);
    } catch (error) {
      const failure = error instanceof InstallationContextMismatch ? MISMATCH : problemFromError(error);
      setProblem(failure.code === "operation_indeterminate" ? { ...failure, detail: `${failure.detail} Check the audit log before retrying.` } : failure);
    } finally {
      setPending(false);
    }
  }
  return (
    <ImpactDialog
      acknowledgement="I understand this immediately and permanently revokes this installation's sessions, refresh tokens and keys."
      confirmLabel="Revoke Installation"
      description="Revokes this older installation together with its active sessions, refresh tokens and verification keys in one operation."
      facts={[["Takes effect", "Immediately after the server accepts it"], ["Undo", "None. The app must start a new installation."]]}
      impacts={[{ count: installation.status === "active" ? 1 : 0, label: "active installation" }]}
      maxReason={100}
      minReason={1}
      onCancel={onClose}
      onConfirm={({ reason }) => void confirm(reason)}
      pending={pending}
      preserved="the user's other installations"
      reasonHint="Sent with the revocation (100 characters). Don't paste tokens or personal data."
      scope={<>Reach: <code className="lw-code-inline">{installation.id}</code></>}
      targetId={installation.id}
      title="Revoke this installation?"
    >
      <Notice title="No server preview" tone="info">The server has no preview for installation actions, so the state shown here isn't checked again before it runs.</Notice>
      {problem ? <ProblemNotice problem={problem} /> : null}
    </ImpactDialog>
  );
}

function OlderInstallsView() {
  const session = useConsoleSession();
  const compatibility = useConsoleCompatibility();
  const workspace = useWorkspace();
  const queryClient = useQueryClient();
  const environmentID = workspace.environment?.id ?? "";
  const search = InstallationRouteSearchSchema.parse(workspace.search);
  const linkSearch = { application: search.application, environment: search.environment, organization: search.organization };
  const canRevoke = compatibility.mutationAllowed && (session.data?.session?.capabilities.includes("revoke_installations") ?? false);
  const [reviewing, setReviewing] = useState<Installation>();
  const [outcome, setOutcome] = useState<string>();
  const [now] = useState(() => Date.now());
  const scopeMismatch = Boolean(search.environment_id && search.environment_id !== environmentID);

  const list = useInfiniteQuery({
    enabled: Boolean(environmentID) && !scopeMismatch,
    getNextPageParam: (last: { page: { has_more: boolean; next_cursor?: string } }) => (last.page.has_more ? last.page.next_cursor : undefined),
    initialPageParam: search.cursor as string | undefined,
    queryFn: async ({ pageParam }) => {
      const page = (await adminRequest(queryPath("/admin/v1/installations", { cursor: pageParam, environment_id: environmentID, page_size: "50" }), InstallationPageSchema)).data;
      if (page.items.some((item) => item.environment_id !== environmentID)) throw new InstallationContextMismatch("installation_context");
      return page;
    },
    queryKey: ["installations", environmentID, search.cursor ?? ""],
    refetchOnWindowFocus: false
  });
  const items = list.data?.pages.flatMap((page) => page.items) ?? [];
  const detail = useQuery({
    enabled: Boolean(environmentID && search.installation_id) && !scopeMismatch,
    queryFn: async () => {
      const response = await adminRequest(`/admin/v1/installations/${search.installation_id}`, InstallationSchema);
      if (response.data.id !== search.installation_id || response.data.environment_id !== environmentID) throw new InstallationContextMismatch("installation_context");
      return response.data;
    },
    queryKey: ["installation", environmentID, search.installation_id],
    refetchOnWindowFocus: false,
    retry: false
  });
  const selected = detail.data && detail.data.id === search.installation_id ? detail.data : undefined;
  const problem = scopeMismatch || list.error instanceof InstallationContextMismatch ? MISMATCH : list.error ? problemFromError(list.error) : undefined;

  function open(installationID: string | undefined): void {
    setOutcome(undefined);
    setReviewing(undefined);
    workspace.updateSearch({ environment_id: installationID ? environmentID : undefined, installation_id: installationID }, { replace: false });
  }

  const columns: Array<Column<Installation>> = [
    { header: "Installation", key: "id", render: (item) => <span className="lw-an-key"><span>{PLATFORM_LABEL[item.platform] ?? words(item.platform)} <Badge color="orange" variant="soft">Legacy</Badge></span><span className="lw-faint lw-mono" title={item.id}>{shortId(item.id)}</span></span> },
    { header: "User", key: "user", render: (item) => <span className="lw-mono lw-mono--sm" title={item.user_id}>{shortId(item.user_id)}</span> },
    { header: "Trust", key: "trust", render: (item) => item.trust_level === "debug" ? <span className="lw-text-danger">Debug</span> : words(item.trust_level) },
    { header: "Status", key: "status", render: (item) => <StatusBadge status={item.status === "active" ? "active" : "revoked"}>{capitalize(item.status)}</StatusBadge> },
    { header: "Last seen", key: "last", render: (item) => item.last_seen_at ? <span className="lw-secondary lw-num" title={formatUtc(item.last_seen_at)}>{formatClock(item.last_seen_at, now)}</span> : <span className="lw-faint">—</span> }
  ];

  return (
    <div className="lw-page lw-installations">
      <PageHeader description="Installations from app versions that predate installation families. Each moves into a family the next time it verifies with a current SDK." title="Older installs" />
      <Toolbar className="lw-toolbar--wrap" search={<GoToForm />}><span className="lw-secondary lw-note">Listed in server order; the API can't filter or sort these.</span></Toolbar>
      {problem ? <div className="lw-page-notice"><ProblemNotice problem={problem} /></div> : null}
      {list.isPending && !scopeMismatch ? <p className="lw-page-status" role="status">Loading older installs…</p> : items.length ? (
        <DataTable caption="Older installs" columns={columns} onSelect={(item) => open(item.id)} rowKey={(item) => item.id} rows={items} selectedKey={search.installation_id} />
      ) : list.isSuccess ? <div className="lw-page-empty"><EmptyState icon="mobile" orientation="horizontal" title="No older installs">Every installation in this environment uses a current SDK.</EmptyState></div> : null}
      <div className="lw-rq-foot">
        <span>{items.length ? `${items.length} shown${list.hasNextPage ? " · more available" : " · that's all"}` : ""}</span>
        {list.hasNextPage ? <Button loading={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()} size="sm">Load More</Button> : null}
      </div>
      {search.installation_id ? (
        <div className="lw-drawer-dock">
          <DetailPanel
            actions={selected && canRevoke && selected.status === "active" ? <Button destructive onClick={() => setReviewing(selected)} size="sm">Revoke Installation</Button> : undefined}
            className="lw-request-drawer"
            mono
            onClose={() => open(undefined)}
            subtitle={selected ? <><StatusBadge status={selected.status === "active" ? "active" : "revoked"}>{capitalize(selected.status)}</StatusBadge><Badge color="orange" variant="soft">Legacy</Badge></> : undefined}
            title={search.installation_id}
          >
            {outcome ? <Notice title="Done" tone="success">{outcome}</Notice> : null}
            {selected ? (
              <Properties columns={2} items={[
                { label: "User", value: <Link className="lw-link lw-mono lw-mono--sm" search={{ ...linkSearch, user_id: selected.user_id }} to="/users">{selected.user_id}</Link> },
                { label: "Platform", value: PLATFORM_LABEL[selected.platform] ?? words(selected.platform) },
                { label: "Trust", value: selected.trust_level === "debug" ? <span className="lw-text-danger">Debug</span> : words(selected.trust_level) },
                { label: "Trust provider", value: selected.attestation_provider ?? <span className="lw-faint">Not recorded</span> },
                { label: "Trust expires", value: selected.trust_expires_at ? <span title={formatUtc(selected.trust_expires_at)}>{formatClock(selected.trust_expires_at, now)}</span> : <span className="lw-faint">Not recorded</span> },
                { label: "Installed", value: <span title={formatUtc(selected.created_at)}>{formatClock(selected.created_at, now)}</span> },
                { label: "Revoked", value: selected.revoked_at ? formatClock(selected.revoked_at, now) : <span className="lw-faint">No</span> }
              ]} />
            ) : detail.error ? <ProblemNotice problem={detail.error instanceof InstallationContextMismatch ? MISMATCH : problemFromError(detail.error)} /> : <p role="status">Loading installation…</p>}
          </DetailPanel>
        </div>
      ) : null}
      {reviewing ? <RevokeReview environmentID={environmentID} installation={reviewing} onClose={() => setReviewing(undefined)} onDone={(updated) => {
        queryClient.setQueryData(["installation", environmentID, updated.id], updated);
        void queryClient.invalidateQueries({ queryKey: ["installations", environmentID] });
        setReviewing(undefined);
        setOutcome(`Installation ${updated.id} revoked.`);
      }} /> : null}
    </div>
  );
}

function OlderInstallsWorkspace() {
  const session = useConsoleSession();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <EnvironmentRequired><OlderInstallsView /></EnvironmentRequired>;
}

/** Users & Installs → Older installs, from GET /admin/v1/installations (wire-1 installations). */
export function InstallationsPage() {
  return <OlderInstallsWorkspace />;
}
