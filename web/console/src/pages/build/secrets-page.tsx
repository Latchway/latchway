import { useInfiniteQuery } from "@tanstack/react-query";
import { useCapabilities } from "../../app/permissions";
import { type FormEvent, useRef, useState } from "react";
import { z } from "zod";

import { adminRequest, queryPath } from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { type SecretResource, type SecretResourcePage, SecretResourcePageSchema, SecretResourceSchema } from "../../api/resources";
import { useConsoleSession } from "../../api/session";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useOptionalWorkspace, useWorkspace } from "../../app/workspace-context-value";
import { Badge, Button, type Column, ConfirmDialog, DataTable, DetailPanel, EmptyState, Field, Input, Notice, PageHeader } from "../../ui";
import { COLLECTIONS } from "../changes/config-diff";
import { AccessRequired, ProblemNotice } from "../control-plane-pages";
import type { JSONRecord } from "../configuration-slice";
import { useEnvironmentDraft } from "./environment-draft";

const NAME = /^[a-z][a-z0-9_-]{0,62}$/;
const ROTATION_DAYS = 90;
const wallClock = (): number => Date.now();

function referencesIn(value: unknown, name: string): boolean {
  if (typeof value === "string") return value === `secret/${name}`;
  if (Array.isArray(value)) return value.some((item) => referencesIn(item, name));
  if (value && typeof value === "object") return Object.values(value).some((item) => referencesIn(item, name));
  return false;
}

/** Where a secret is referenced, e.g. "AI connection openai (live)". */
function secretUsage(name: string, live: JSONRecord | undefined, draft: JSONRecord | undefined): string[] {
  const found = new Map<string, Set<string>>();
  for (const [label, document] of [["live", live], ["draft", draft]] as const) {
    const spec = document?.spec;
    if (!spec || typeof spec !== "object") continue;
    for (const [key, items] of Object.entries(spec as JSONRecord)) {
      if (!Array.isArray(items)) continue;
      for (const item of items) {
        if (!item || typeof item !== "object" || !referencesIn(item, name)) continue;
        const where = `${COLLECTIONS[key]?.label ?? key} ${String((item as JSONRecord).id ?? "")}`.trim();
        found.set(where, new Set([...(found.get(where) ?? []), label]));
      }
    }
  }
  return [...found.entries()].map(([where, places]) => `${where} (${places.size === 2 ? "live and draft" : [...places][0]})`);
}

function age(secret: SecretResource, now: number): number {
  return Math.floor((now - Date.parse(secret.rotated_at ?? secret.created_at)) / 86_400_000);
}

function SecretDrawer({ environmentID, existing, onClose, onDone, rotate }: { environmentID: string; existing: readonly string[]; onClose: () => void; onDone: (secret: SecretResource) => void; rotate?: { inUse: string[]; secret: SecretResource } }) {
  const value = useRef<HTMLInputElement>(null);
  const [name, setName] = useState("");
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const taken = !rotate && existing.includes(name);

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const secret = value.current?.value ?? "";
    if (value.current) value.current.value = "";
    if (!secret) return setProblem({ code: "request_invalid", detail: "Enter the value.", retryable: false, status: 0, title: "Value needed" });
    setBusy(true);
    setProblem(undefined);
    try {
      const saved = rotate
        ? (await adminRequest(`/admin/v1/secrets/${rotate.secret.id}/rotate`, SecretResourceSchema, { body: { value: secret }, method: "POST" })).data
        : (await adminRequest("/admin/v1/secrets", SecretResourceSchema, { body: { environment_id: environmentID, name, value: secret }, method: "POST" })).data;
      if (saved.environment_id !== environmentID) throw new Error("The saved secret belongs to another environment.");
      onDone(saved);
    } catch (failure) {
      setProblem(failure instanceof Error && !("problem" in failure) ? { code: "context_mismatch", detail: failure.message, retryable: false, status: 0, title: "Unexpected secret" } : problemFromError(failure));
    } finally {
      if (value.current) value.current.value = "";
      setBusy(false);
    }
  }

  return (
    <DetailPanel className="lw-request-drawer" onClose={onClose} subtitle={<span className="lw-faint">Values are write-only: no one can read them back</span>} title={rotate ? `Rotate ${rotate.secret.name}` : "Add secret"}>
      <form autoComplete="off" className="lw-stack" onSubmit={(event) => void submit(event)}>
        {rotate ? (
          <>
            <Notice tone="info">Replaces version {rotate.secret.version}. New requests use the new value at once.</Notice>
            {rotate.inUse.length ? <Notice tone="warning">In use by {rotate.inUse.join(", ")}. Create the new key at the provider first, then paste it here, so requests never use a revoked key.</Notice> : null}
          </>
        ) : (
          <Field error={taken ? "This name already exists here. Rotate it instead." : name && !NAME.test(name) ? "Lowercase letters, digits, - or _, starting with a letter." : undefined} hint="Configuration refers to it as secret/<name>. Names of deleted secrets can't be reused." id="secret-name" label="Name">
            <Input id="secret-name" maxLength={63} mono onChange={(event) => setName(event.target.value)} required value={name} />
          </Field>
        )}
        <Field hint="Encrypted when saved, and cleared from this browser right after." id="secret-value" label={rotate ? "New value" : "Value"}>
          <div className="lw-input-box"><input autoComplete="new-password" className="lw-input lw-input--mono" id="secret-value" maxLength={1_048_576} name="value" ref={value} required type="password" /></div>
        </Field>
        {problem ? <ProblemNotice problem={problem} /> : null}
        <div className="lw-row"><Button onClick={onClose}>Cancel</Button><Button disabled={!rotate && (!NAME.test(name) || taken)} loading={busy} type="submit" variant="primary">{rotate ? "Rotate" : "Add Secret"}</Button></div>
      </form>
    </DetailPanel>
  );
}

function SecretsView() {
  const workspace = useWorkspace();
  const compatibility = useConsoleCompatibility();
  const draft = useEnvironmentDraft();
  const environmentID = workspace.environment?.id ?? "";
  const { can } = useCapabilities();
  const canInspect = can("manage_secrets");
  const canManage = canInspect && compatibility.mutationAllowed && workspace.application?.status !== "disabled" && workspace.environment?.status !== "disabled";
  const [now] = useState(wallClock);
  const [adding, setAdding] = useState(false);
  const [rotating, setRotating] = useState<SecretResource>();
  const [deleting, setDeleting] = useState<SecretResource>();
  const [typed, setTyped] = useState("");
  const [notice, setNotice] = useState<string>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);
  const secrets = useInfiniteQuery({
    enabled: canInspect && Boolean(environmentID),
    getNextPageParam: (page: SecretResourcePage) => (page.page.has_more ? page.page.next_cursor : undefined),
    initialPageParam: undefined as string | undefined,
    queryFn: async ({ pageParam }): Promise<SecretResourcePage> => {
      const page = (await adminRequest(queryPath("/admin/v1/secrets", { cursor: pageParam, environment_id: environmentID, page_size: "100" }), SecretResourcePageSchema)).data;
      if (page.items.some((item) => item.environment_id !== environmentID)) throw new Error("A secret didn't belong to this environment.");
      return page;
    },
    queryKey: ["environment", environmentID, "secrets"],
    retry: false
  });
  const items = secrets.data?.pages.flatMap((page) => page.items) ?? [];
  const usage = (secret: SecretResource) => secretUsage(secret.name, draft.activeDocument, draft.draft ? (draft.draft.document as JSONRecord) : undefined);
  const stale = items.filter((secret) => age(secret, now) >= ROTATION_DAYS);

  async function remove(secret: SecretResource): Promise<void> {
    setBusy(true);
    setProblem(undefined);
    try {
      await adminRequest(`/admin/v1/secrets/${secret.id}`, z.undefined(), { method: "DELETE" });
      setDeleting(undefined);
      setNotice(`${secret.name} was deleted. Its name can't be used again in this environment.`);
      await secrets.refetch();
    } catch (failure) {
      setProblem(problemFromError(failure));
    } finally {
      setBusy(false);
    }
  }

  const columns: Array<Column<SecretResource>> = [
    { header: "Name", key: "name", render: (secret) => <span className="lw-rq-model"><span className="lw-mono lw-mono--sm">{secret.name}</span><span className="lw-faint">{secret.id}</span></span> },
    { align: "right", header: "Version", key: "version", render: (secret) => secret.version },
    { header: "Last rotated", key: "rotated", render: (secret) => <span className="lw-row lw-row--tight"><span className="lw-note">{new Date(secret.rotated_at ?? secret.created_at).toLocaleDateString()}</span>{age(secret, now) >= ROTATION_DAYS ? <Badge color="orange" variant="soft">{age(secret, now)} days</Badge> : null}</span> },
    { header: "Used by", key: "used", render: (secret) => { const where = usage(secret); return where.length ? <span className="lw-note">{where.join(", ")}</span> : <span className="lw-faint">Not referenced</span>; } },
    { align: "right", header: "", key: "actions", render: (secret) => canManage ? <span className="lw-row lw-row--tight"><Button onClick={() => setRotating(secret)} size="sm" variant="ghost">Rotate</Button><Button destructive onClick={() => { setDeleting(secret); setTyped(""); setProblem(undefined); }} size="sm" variant="ghost">Delete</Button></span> : null }
  ];

  if (!canInspect) return <div className="lw-page"><PageHeader description="Provider keys and verification credentials for this environment." title="Secrets" /><div className="lw-page-empty"><EmptyState icon="lock" orientation="horizontal" title="Capability needed">Secrets need the <code className="lw-code-inline">manage_secrets</code> capability (Admin role).</EmptyState></div></div>;
  const deletingUsage = deleting ? usage(deleting) : [];
  return (
    <div className="lw-page lw-collection">
      <PageHeader actions={<Button disabled={!canManage} icon="plus" onClick={() => setAdding(true)} variant="primary">Add Secret</Button>} description="Provider keys and verification credentials for this environment. Values are write-only: no one can read them back, not even partially." title="Secrets" />
      {notice ? <div className="lw-page-notice"><Notice tone="success">{notice}</Notice></div> : null}
      {stale.length ? <div className="lw-page-notice"><Notice tone="warning">Not rotated in {ROTATION_DAYS} days: {stale.map((secret) => secret.name).join(", ")}.</Notice></div> : null}
      {secrets.error ? <div className="lw-page-notice"><ProblemNotice problem={problemFromError(secrets.error)} /></div> : null}
      {secrets.isPending ? <p className="lw-page-status" role="status">Loading secrets…</p> : items.length ? (
        <DataTable caption="Secrets" columns={columns} rowKey={(secret) => secret.id} rows={items} />
      ) : <div className="lw-page-empty"><EmptyState icon="key" orientation="horizontal" title="No secrets yet">Add a provider key here, or let Add Connection store one for you.</EmptyState></div>}
      {secrets.hasNextPage ? <div className="lw-page-foot"><Button loading={secrets.isFetchingNextPage} onClick={() => void secrets.fetchNextPage()} size="sm">Load More</Button></div> : null}
      <p className="lw-secondary lw-note lw-page-foot">Deleted names aren&apos;t listed by the Admin API; reusing one is refused by the server.</p>
      {adding && canManage ? <div className="lw-drawer-dock"><SecretDrawer environmentID={environmentID} existing={items.map((secret) => secret.name)} onClose={() => setAdding(false)} onDone={(secret) => { setAdding(false); setNotice(`${secret.name} was added. Refer to it as secret/${secret.name}.`); void secrets.refetch(); }} /></div> : null}
      {rotating && canManage ? <div className="lw-drawer-dock"><SecretDrawer environmentID={environmentID} existing={[]} onClose={() => setRotating(undefined)} onDone={(secret) => { setRotating(undefined); setNotice(`${secret.name} is now version ${secret.version}.`); void secrets.refetch(); }} rotate={{ inUse: usage(rotating), secret: rotating }} /></div> : null}
      {deleting && deletingUsage.length ? (
        <ConfirmDialog confirmLabel="Close" description="Change these first, in AI Connections or Client Trust, then delete it." onCancel={() => setDeleting(undefined)} onConfirm={() => setDeleting(undefined)} title={`${deleting.name} is still in use`}>
          <ul className="lw-issue-list">{deletingUsage.map((where) => <li key={where}>{where}</li>)}</ul>
        </ConfirmDialog>
      ) : deleting ? (
        <ConfirmDialog confirmDisabled={typed !== deleting.name} confirmLabel="Delete Secret" description={`Deletes version ${deleting.version} and every earlier one. The name can never be used again in this environment, and there's no undo.`} destructive onCancel={() => setDeleting(undefined)} onConfirm={() => void remove(deleting)} pending={busy} title={`Delete ${deleting.name}?`}>
          <Field id="secret-confirm" label={<>Type <code className="lw-code-inline">{deleting.name}</code> to confirm</>}><Input autoComplete="off" id="secret-confirm" mono onChange={(event) => setTyped(event.target.value)} value={typed} /></Field>
          {problem ? <ProblemNotice problem={problem} /> : null}
        </ConfirmDialog>
      ) : null}
    </div>
  );
}

/** Build → AI Connections → Secrets. */
export function SecretsPage() {
  const session = useConsoleSession();
  const workspace = useOptionalWorkspace();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <EnvironmentRequired><SecretsView key={`${workspace?.application?.id ?? "none"}:${workspace?.environment?.id ?? "none"}`} /></EnvironmentRequired>;
}
