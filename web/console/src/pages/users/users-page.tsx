import { useInfiniteQuery, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCapabilities } from "../../app/permissions";
import { Link, useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";

import {
  adminRequest,
  type ApplicationUser,
  type EffectiveConfiguration,
  getUserEffectiveConfiguration,
  InstallationFamilyPageSchema,
  queryPath,
  RequestPageSchema,
  type UserOperationAction,
  UserPageSchema,
  UserSchema
} from "../../api/admin";
import { type AdminProblem, problemFromError } from "../../api/auth";
import { useConsoleSession } from "../../api/session";
import { useConsoleCompatibility } from "../../app/console-compatibility-context";
import { UserRouteSearchSchema } from "../../app/route-search";
import { EnvironmentRequired } from "../../app/workspace-context";
import { useWorkspace } from "../../app/workspace-context-value";
import { MenuButton } from "../../components/menu-button";
import {
  Badge,
  Button,
  type Column,
  DataTable,
  DetailPanel,
  EmptyState,
  Field,
  Input,
  type MenuEntry,
  Notice,
  PageHeader,
  Properties,
  StatusBadge,
  Toolbar
} from "../../ui";
import { formatCount, formatMoney, recorded } from "../analytics/usage-model";
import { AccessRequired, EffectiveConfigurationPanel, ProblemNotice } from "../control-plane-pages";
import { capitalize, formatClock, formatUtc, outcomeStatus, shortId } from "../requests/request-format";
import { BulkSignInReview, type OperationOutcome, UserOperationReview, ViewOnlyNotice } from "./user-review";
import { GoToForm } from "./go-to-form";
import { ACTION_TITLE, claimText, familySignals, maskClaim, signalBadgeColor } from "./users-model";

const PAGE_SIZE = "50";
const BULK_LIMIT = 50;

const USER_CONTEXT_PROBLEM: AdminProblem = { code: "invalid_response", detail: "The user detail did not match the selected environment and pseudonymous user ID.", retryable: true, status: 0, title: "User context mismatch" };

class UserContextMismatch extends Error {}

type Intent = { action: UserOperationAction } | { to: "/installation-families" | "/user-overrides" };

interface Situation {
  id: string;
  intent: Intent;
  label: string;
  note: string;
}

/** Operators know the problem, not the action: each situation says what it won't do, then opens the matching review. */
function situations(user: ApplicationUser): Situation[] {
  if (user.status === "blocked") {
    return [
      { id: "mistake", intent: { action: "unblock" }, label: "Blocked by mistake", note: "Unblocking doesn't restore sessions the block revoked; the user signs in again." },
      { id: "quota", intent: { to: "/user-overrides" }, label: "Needs more quota for a while", note: "An override changes limits only; it doesn't unblock the user." }
    ];
  }
  return [
    { id: "abuse", intent: { action: "block" }, label: "Account compromised or abusive", note: "Blocking refuses every request but doesn't delete the user's records." },
    { id: "claims", intent: { action: "require_reauthentication" }, label: "Plan or claims changed but aren't applied", note: "Signing in again picks up new claims; it doesn't change them." },
    { id: "modified", intent: { action: "require_app_reverification" }, label: "Suspect a modified app or rooted device", note: "Re-verification asks every installation to prove it's genuine; a failing one stops refreshing." },
    { id: "lost", intent: { to: "/installation-families" }, label: "One device lost or stolen", note: "Pick that installation and revoke it; the user's other devices keep working." },
    { id: "part", intent: { to: "/installation-families" }, label: "One widget or extension misbehaving", note: "Pick the installation, then revoke only that part." },
    { id: "quota", intent: { to: "/user-overrides" }, label: "Needs more quota for a while", note: "An override changes limits only, until the date you choose." }
  ];
}

function Claims({ claims }: { claims: Record<string, unknown> }) {
  const [shown, setShown] = useState(false);
  const keys = Object.keys(claims).sort();
  if (!keys.length) return <p className="lw-secondary lw-note">No normalized claims are kept for this user.</p>;
  return (
    <div className="lw-stack lw-stack--tight">
      <Properties columns={2} items={keys.map((key) => ({ label: key, value: <span className="lw-mono lw-mono--sm">{shown ? claimText(claims[key]) : maskClaim(claims[key])}</span> }))} />
      <div><Button onClick={() => setShown(!shown)} size="sm">{shown ? "Hide Values" : "Show Values"}</Button></div>
      <p className="lw-secondary lw-note">These are the normalized claims Latchway keeps, as mapped in Client Trust → User sign-in. Raw sign-in subjects and tokens are never stored.</p>
    </div>
  );
}

function CheckAccess({ environmentID, user }: { environmentID: string; user: ApplicationUser }) {
  const [feature, setFeature] = useState("");
  const [surface, setSurface] = useState<"latest" | "installation" | "component">("latest");
  const [surfaceID, setSurfaceID] = useState("");
  const [inputTokens, setInputTokens] = useState("");
  const [outputTokens, setOutputTokens] = useState("");
  const [streaming, setStreaming] = useState(false);
  const [result, setResult] = useState<EffectiveConfiguration>();
  const [problem, setProblem] = useState<AdminProblem>();
  const [busy, setBusy] = useState(false);

  async function explain(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setProblem(undefined);
    try {
      const response = await getUserEffectiveConfiguration(user.id, {
        ...(surface === "component" ? { componentID: surfaceID } : {}),
        environmentID,
        ...(inputTokens ? { estimatedInputTokens: Number(inputTokens) } : {}),
        feature,
        ...(surface === "installation" ? { installationID: surfaceID } : {}),
        ...(outputTokens ? { maximumOutputTokens: Number(outputTokens) } : {}),
        streaming
      });
      if (response.data.subject.id !== user.id || response.data.environment_id !== environmentID) throw new UserContextMismatch("effective_context");
      setResult(response.data);
    } catch (error) {
      setResult(undefined);
      setProblem(error instanceof UserContextMismatch ? USER_CONTEXT_PROBLEM : problemFromError(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="lw-stack lw-stack--tight">
      <form className="lw-form-grid lw-form-grid--end" onSubmit={(event) => void explain(event)}>
        <Field id="check-feature" label="Feature"><Input id="check-feature" onChange={(event) => setFeature(event.target.value)} pattern="[a-z][a-z0-9_\-]{0,62}" required value={feature} /></Field>
        <Field id="check-surface" label="Client surface">
          <select className="lw-select" id="check-surface" onChange={(event) => { setSurface(event.target.value as typeof surface); setSurfaceID(""); }} value={surface}>
            <option value="latest">Latest active session</option>
            <option value="installation">Installation</option>
            <option value="component">Component</option>
          </select>
        </Field>
        {surface !== "latest" ? <Field id="check-surface-id" label={surface === "installation" ? "Installation ID" : "Component ID"}><Input id="check-surface-id" onChange={(event) => setSurfaceID(event.target.value)} required value={surfaceID} /></Field> : null}
        <Field id="check-input" label="Estimated input tokens"><Input id="check-input" max="2147483647" min="0" onChange={(event) => setInputTokens(event.target.value)} step="1" type="number" value={inputTokens} /></Field>
        <Field id="check-output" label="Requested output tokens"><Input id="check-output" max="2147483647" min="0" onChange={(event) => setOutputTokens(event.target.value)} step="1" type="number" value={outputTokens} /></Field>
        <label className="lw-check"><input checked={streaming} onChange={(event) => setStreaming(event.target.checked)} type="checkbox" /><span>Streaming request</span></label>
        <div><Button loading={busy} size="sm" type="submit">Check Access</Button></div>
      </form>
      <ProblemNotice problem={problem} />
      {result ? <EffectiveConfigurationPanel configuration={result} /> : null}
    </div>
  );
}

interface UserDrawerProps {
  canMutate: boolean;
  environmentID: string;
  environmentKind?: string;
  linkSearch: Record<string, string | undefined>;
  onAction: (action: UserOperationAction) => void;
  onClose: () => void;
  outcome?: string;
  user: ApplicationUser;
}

function UserDrawer({ canMutate, environmentID, environmentKind, linkSearch, onAction, onClose, outcome, user }: UserDrawerProps) {
  const navigate = useNavigate();
  const [now] = useState(() => Date.now());
  const [chooser, setChooser] = useState(false);
  const families = useQuery({
    queryFn: async () => (await adminRequest(queryPath("/admin/v1/installation-families", { environment_id: environmentID, page_size: "50", user_id: user.id }), InstallationFamilyPageSchema)).data,
    queryKey: ["user-families", environmentID, user.id],
    retry: false
  });
  const recent = useQuery({
    queryFn: async () => (await adminRequest(queryPath("/admin/v1/requests", { environment_id: environmentID, page_size: "5", user_id: user.id }), RequestPageSchema)).data,
    queryKey: ["user-requests", environmentID, user.id],
    retry: false
  });
  const familyItems = families.data?.items ?? [];
  const active = familyItems.filter((family) => family.status === "active").length;
  const requestTotal = familyItems.reduce((sum, family) => sum + family.request_count, 0);
  const costs = familyItems.map((family) => recorded(family.usage, "cost_nano_usd"));
  const costTotal = costs.some((cost) => cost === null) ? null : costs.reduce<number>((sum, cost) => sum + (cost ?? 0), 0);
  const blocked = user.status === "blocked";
  const actionEntries: MenuEntry[] = [
    { heading: "Access", kind: "heading" },
    { destructive: !blocked, label: blocked ? "Unblock" : "Block", onSelect: () => onAction(blocked ? "unblock" : "block") },
    ...(blocked ? [] : [
      { label: "Require Sign-in", onSelect: () => onAction("require_reauthentication") },
      { label: "Require App Re-verification", onSelect: () => onAction("require_app_reverification") }
    ] satisfies MenuEntry[]),
    { kind: "separator" },
    { heading: "Limits", kind: "heading" },
    { label: "Plan Override", onSelect: () => void navigate({ search: { ...linkSearch, user: user.id }, to: "/user-overrides" }) }
  ];

  return (
    <DetailPanel
      actions={canMutate ? <>
        <Button onClick={() => setChooser(!chooser)} size="sm">What's Going On?</Button>
        <MenuButton entries={actionEntries} label="Actions" size="sm">Actions</MenuButton>
      </> : undefined}
      className="lw-request-drawer"
      mono
      onClose={onClose}
      sections={[
        ...(outcome ? [{ content: <Notice title="Done" tone="success">{outcome}</Notice> }] : []),
        ...(!canMutate ? [{ content: <ViewOnlyNotice /> }] : []),
        ...(chooser && canMutate ? [{
          content: (
            <ul className="lw-intents">
              {situations(user).map((situation) => (
                <li key={situation.id}>
                  <div><strong>{situation.label}</strong><span>{situation.note}</span></div>
                  <Button onClick={() => {
                    setChooser(false);
                    if ("action" in situation.intent) onAction(situation.intent.action);
                    else void navigate({ search: situation.intent.to === "/installation-families" ? { ...linkSearch, environment_id: environmentID, user_id: user.id } : { ...linkSearch, user: user.id }, to: situation.intent.to });
                  }} size="sm">{"action" in situation.intent ? ACTION_TITLE[situation.intent.action] : situation.intent.to === "/user-overrides" ? "Plan Override" : "Pick Installation"}</Button>
                </li>
              ))}
            </ul>
          ),
          title: "What's going on?"
        }] : []),
        {
          content: <Properties columns={2} items={[
            { label: "User ID", value: <span className="lw-mono lw-mono--sm">{user.id}</span> },
            { label: "Status", value: <StatusBadge status={blocked ? "blocked" : "active"} /> },
            { label: "Signed in with", value: user.identity_providers.length ? user.identity_providers.join(", ") : <span className="lw-faint">Not recorded</span> },
            { label: "Plan override", value: user.limit_plan_override ? <Badge color="accent" variant="soft">Override active</Badge> : <span className="lw-faint">None</span> },
            { label: "First seen", value: <span title={formatUtc(user.created_at)}>{formatClock(user.created_at, now)}</span> },
            { label: "Last seen", value: user.last_seen_at ? <span title={formatUtc(user.last_seen_at)}>{formatClock(user.last_seen_at, now)}</span> : <span className="lw-faint">Not recorded</span> },
            { label: "Installations", value: families.data ? `${active} active · ${familyItems.length}${families.data.page.has_more ? "+" : ""} total` : "Loading…" }
          ]} />,
          title: "Identity"
        },
        { content: <Claims claims={user.normalized_claims} />, title: "Claims" },
        {
          content: families.error ? <ProblemNotice problem={problemFromError(families.error)} /> : (
            <div className="lw-stack lw-stack--tight">
              {familyItems.length ? <p className="lw-secondary lw-note">{formatCount(requestTotal)} requests · {formatMoney(costTotal)} recorded, summed from these installations (there's no per-user usage total).</p> : null}
              {familyItems.length ? (
                <ul className="lw-rank">
                  {familyItems.map((family) => (
                    <li key={family.id}>
                      <span className="lw-an-key">
                        <Link className="lw-link lw-mono lw-mono--sm" search={{ ...linkSearch, environment_id: environmentID, family_id: family.id }} to="/installation-families">{family.id}</Link>
                        <span className="lw-row lw-row--tight">
                          <span className="lw-faint">{family.platform.replaceAll("_", " ")} · {family.component_count} part{family.component_count === 1 ? "" : "s"}</span>
                          {familySignals(family, environmentKind, now).map((signal) => <Badge color={signalBadgeColor(signal.severity)} key={signal.id} variant="soft">{signal.label}</Badge>)}
                        </span>
                      </span>
                      <StatusBadge status={family.status === "active" ? "active" : family.status === "revoked" ? "revoked" : "disabled"}>{capitalize(family.status)}</StatusBadge>
                      <strong className="lw-num">{formatCount(family.request_count)}</strong>
                    </li>
                  ))}
                </ul>
              ) : families.isPending ? <p className="lw-secondary lw-note" role="status">Loading installations…</p> : <p className="lw-secondary lw-note">No installations recorded for this user.</p>}
            </div>
          ),
          title: "Installations"
        },
        {
          content: recent.error ? <ProblemNotice problem={problemFromError(recent.error)} /> : (
            <div className="lw-stack lw-stack--tight">
              {recent.data?.items.length ? (
                <ul className="lw-rank">
                  {recent.data.items.map((request) => (
                    <li key={request.id}>
                      <span className="lw-an-key">
                        <Link className="lw-link lw-mono lw-mono--sm" search={{ ...linkSearch, request: request.id }} to="/requests">{shortId(request.id)}</Link>
                        <span className="lw-faint">{request.feature} · {formatClock(request.started_at, now)}</span>
                      </span>
                      <StatusBadge status={outcomeStatus(request.status)}>{capitalize(request.status)}</StatusBadge>
                      <span />
                    </li>
                  ))}
                </ul>
              ) : <p className="lw-secondary lw-note">{recent.isPending ? "Loading requests…" : "No requests from this user."}</p>}
              <div><Link className="lw-link" search={{ ...linkSearch, range: "7d", user_id: user.id }} to="/requests">See all requests from this user · last 7 days</Link></div>
            </div>
          ),
          title: "Recent requests"
        },
        { content: <CheckAccess environmentID={environmentID} user={user} />, title: "What they can call" },
        {
          content: <Link className="lw-link" search={{ ...linkSearch, environment_id: environmentID, resource_id: user.id }} to="/audit">Open this user's audit events</Link>,
          title: "Activity"
        }
      ]}
      subtitle={<><StatusBadge status={blocked ? "blocked" : "active"} /><span>{user.identity_providers.join(", ") || "No sign-in provider recorded"}</span></>}
      title={user.id}
    />
  );
}

function UsersView() {
  const compatibility = useConsoleCompatibility();
  const workspace = useWorkspace();
  const queryClient = useQueryClient();
  const environment = workspace.environment;
  const environmentID = environment?.id ?? "";
  const search = UserRouteSearchSchema.parse(workspace.search);
  const linkSearch = { application: search.application, environment: search.environment, organization: search.organization };
  const { can } = useCapabilities();
  const canMutate = compatibility.mutationAllowed && can("revoke_installations");
  const [review, setReview] = useState<{ action: UserOperationAction; user: ApplicationUser }>();
  const [outcome, setOutcome] = useState<{ message: string; userID: string }>();
  const [selected, setSelected] = useState<string[]>([]);
  const [bulk, setBulk] = useState(false);
  const [now] = useState(() => Date.now());
  const scopeMismatch = Boolean(search.environment_id && search.environment_id !== environmentID);

  const list = useInfiniteQuery({
    enabled: Boolean(environmentID) && !scopeMismatch,
    getNextPageParam: (last: { page: { has_more: boolean; next_cursor?: string } }) => (last.page.has_more ? last.page.next_cursor : undefined),
    initialPageParam: search.cursor as string | undefined,
    queryFn: async ({ pageParam }) => {
      const page = (await adminRequest(queryPath("/admin/v1/users", { cursor: pageParam, environment_id: environmentID, page_size: PAGE_SIZE }), UserPageSchema)).data;
      if (page.items.some((item) => item.environment_id !== environmentID)) throw new UserContextMismatch("user_context");
      return page;
    },
    queryKey: ["users", environmentID, search.cursor ?? ""],
    refetchOnWindowFocus: false
  });
  const users = list.data?.pages.flatMap((page) => page.items) ?? [];

  const detail = useQuery({
    enabled: Boolean(environmentID && search.user_id) && !scopeMismatch,
    queryFn: async () => {
      const response = await adminRequest(queryPath(`/admin/v1/users/${search.user_id}`, { environment_id: environmentID }), UserSchema);
      if (response.data.id !== search.user_id || response.data.environment_id !== environmentID) throw new UserContextMismatch("user_context");
      return response.data;
    },
    queryKey: ["user", environmentID, search.user_id],
    refetchOnWindowFocus: false,
    retry: false
  });
  const problem = scopeMismatch
    ? { ...USER_CONTEXT_PROBLEM, detail: "This link names a different environment than the one selected. Choose that environment in the header." }
    : list.error instanceof UserContextMismatch || detail.error instanceof UserContextMismatch
      ? USER_CONTEXT_PROBLEM
      : list.error ? problemFromError(list.error) : detail.error ? problemFromError(detail.error) : undefined;

  function select(userID: string | undefined): void {
    setOutcome(undefined);
    workspace.updateSearch({ environment_id: undefined, user_id: userID }, { replace: false });
  }

  function applyOutcome(result: OperationOutcome): void {
    queryClient.setQueryData(["user", environmentID, result.user.id], result.user);
    void queryClient.invalidateQueries({ queryKey: ["users", environmentID] });
    setReview(undefined);
    setOutcome({ message: result.message, userID: result.user.id });
  }

  const selectable = users.filter((user) => user.status !== "blocked");
  const toggle = (id: string) => setSelected((current) => current.includes(id) ? current.filter((item) => item !== id) : current.length >= BULK_LIMIT ? current : [...current, id]);
  const columns: Array<Column<ApplicationUser>> = [
    ...(canMutate ? [{
      header: <span className="lw-sr">Select</span>,
      key: "select",
      render: (user: ApplicationUser) => (
        <input
          aria-label={`Select ${user.id}`}
          checked={selected.includes(user.id)}
          disabled={user.status === "blocked" || (!selected.includes(user.id) && selected.length >= BULK_LIMIT)}
          onChange={() => toggle(user.id)}
          onClick={(event) => event.stopPropagation()}
          onKeyDown={(event) => event.stopPropagation()}
          title={user.status === "blocked" ? "Blocked users have no sessions to end" : undefined}
          type="checkbox"
        />
      ),
      width: 40
    }] : []),
    { header: "User", key: "user", render: (user) => <span className="lw-mono lw-mono--sm" title={user.id}>{shortId(user.id)}</span> },
    { header: "Status", key: "status", render: (user) => <StatusBadge status={user.status === "blocked" ? "blocked" : "active"} /> },
    { header: "Plan", key: "plan", render: (user) => user.limit_plan_override ? <Badge color="accent" variant="soft">Override</Badge> : <span className="lw-faint">From claims</span> },
    { header: "Signed in with", key: "providers", render: (user) => user.identity_providers.join(", ") || <span className="lw-faint">—</span> },
    { header: "First seen", key: "first", render: (user) => <span className="lw-secondary lw-num" title={formatUtc(user.created_at)}>{formatClock(user.created_at, now)}</span> },
    { header: "Last seen", key: "last", render: (user) => user.last_seen_at ? <span className="lw-secondary lw-num" title={formatUtc(user.last_seen_at)}>{formatClock(user.last_seen_at, now)}</span> : <span className="lw-faint">—</span> }
  ];
  const selectedUsers = users.filter((user) => selected.includes(user.id));
  const drawerUser = detail.data && detail.data.id === search.user_id ? detail.data : undefined;

  return (
    <div className="lw-page lw-users">
      <PageHeader description="People who signed in to your apps, by their pseudonymous Latchway ID. Users appear on their first verified sign-in; change their state through reviewed actions." title="Users" />
      <Toolbar
        className="lw-toolbar--wrap"
        search={<GoToForm onUser={select} />}
      >
        <span className="lw-secondary lw-note">Listed in server order. The API can't filter, sort or search users yet.</span>
        {canMutate && selected.length ? <>
          <span className="lw-note">{selected.length} selected</span>
          <Button onClick={() => setBulk(true)} size="sm">Require Sign-in…</Button>
          <Button onClick={() => setSelected([])} size="sm" variant="ghost">Clear</Button>
        </> : null}
        {canMutate && !selected.length && selectable.length ? <span className="lw-faint lw-note">Select up to {BULK_LIMIT} users to require sign-in together.</span> : null}
      </Toolbar>

      {problem ? <div className="lw-page-notice"><ProblemNotice problem={problem} /></div> : null}
      {list.isPending && !scopeMismatch ? <p className="lw-page-status" role="status">Loading users…</p> : users.length ? (
        <DataTable caption="Users" columns={columns} onSelect={(user) => select(user.id)} rowKey={(user) => user.id} rows={users} selectedKey={search.user_id} />
      ) : list.isSuccess ? (
        <div className="lw-page-empty"><EmptyState icon="users" orientation="horizontal" title="No users yet">Users appear here the first time someone signs in to your app through Latchway.</EmptyState></div>
      ) : null}
      <div className="lw-rq-foot">
        <span>{users.length ? `${users.length} shown${list.hasNextPage ? " · more available" : " · that's all"}` : ""}</span>
        {list.hasNextPage ? <Button loading={list.isFetchingNextPage} onClick={() => void list.fetchNextPage()} size="sm">Load More</Button> : null}
        <span className="lw-spacer" />
        <span className="lw-faint">There's no total: the users API doesn't count matches.</span>
      </div>

      {search.user_id ? (
        <div className="lw-drawer-dock">
          {drawerUser ? (
            <UserDrawer
              canMutate={canMutate}
              environmentID={environmentID}
              environmentKind={environment?.kind}
              key={drawerUser.id}
              linkSearch={linkSearch}
              onAction={(action) => setReview({ action, user: drawerUser })}
              onClose={() => select(undefined)}
              outcome={outcome?.userID === drawerUser.id ? outcome.message : undefined}
              user={drawerUser}
            />
          ) : (
            <DetailPanel mono onClose={() => select(undefined)} title={search.user_id}>
              {detail.error ? <ProblemNotice problem={detail.error instanceof UserContextMismatch ? USER_CONTEXT_PROBLEM : problemFromError(detail.error).status === 404 ? { ...problemFromError(detail.error), detail: `No user ${search.user_id} in ${workspace.application?.display_name ?? "this application"} · ${environment?.display_name ?? "this environment"}.` } : problemFromError(detail.error)} /> : <p role="status">Loading user…</p>}
            </DetailPanel>
          )}
        </div>
      ) : null}
      {review ? <UserOperationReview action={review.action} environmentID={environmentID} key={`${review.user.id}-${review.action}`} onClose={() => setReview(undefined)} onDone={applyOutcome} user={review.user} /> : null}
      {bulk ? <BulkSignInReview environmentID={environmentID} onClose={() => { setBulk(false); setSelected([]); }} onFinished={() => void queryClient.invalidateQueries({ queryKey: ["users", environmentID] })} users={selectedUsers} /> : null}
    </div>
  );
}

function UsersWorkspace() {
  const session = useConsoleSession();
  if (session.data?.mode !== "configured") return <AccessRequired />;
  return <EnvironmentRequired><UsersView /></EnvironmentRequired>;
}

/** Users & Installs → Users, from GET /admin/v1/users. */
export function UsersPage() {
  return <UsersWorkspace />;
}
