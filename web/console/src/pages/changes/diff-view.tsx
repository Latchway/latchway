import { useQueries } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { type ReactNode, useState } from "react";

import { Badge, Button, buttonClass, Icon } from "../../ui";
import { outcomeText, SAMPLE_PEOPLE, simulate, SIZE_PRESETS } from "../simulator/simulator-model";
import { type DiffEntry, editTarget, type FieldChange, GROUP_LABEL, GROUP_ORDER } from "./config-diff";

function value(input: unknown): string {
  if (input === undefined) return "—";
  return typeof input === "string" ? input : JSON.stringify(input);
}

function FieldDiff({ field }: { field: FieldChange }) {
  const kind = field.list ? (field.list.removed.length && !field.list.added.length ? " lw-fdiff__row--remove" : !field.list.removed.length ? " lw-fdiff__row--add" : "") : field.before === undefined ? " lw-fdiff__row--add" : field.after === undefined ? " lw-fdiff__row--remove" : "";
  return (
    <div className={`lw-fdiff__row${kind}`}>
      <span className="lw-fdiff__label">{field.path}</span>
      {field.list ? (
        <span className="lw-fdiff__vals">{[...field.list.added.map((item) => `+ ${item}`), ...field.list.removed.map((item) => `− ${item}`)].join(", ")}</span>
      ) : <span className="lw-fdiff__vals"><span className="lw-fdiff__before">{value(field.before)}</span><Icon name="arrowRight" size={12} /><span className="lw-fdiff__after">{value(field.after)}</span></span>}
    </div>
  );
}

const STATE_BADGE: Readonly<Record<DiffEntry["state"], ReactNode>> = {
  edited: <Badge color="accent" variant="soft">Edited</Badge>,
  new: <Badge color="orange" variant="soft">New</Badge>,
  removing: <Badge color="red" variant="soft">Deleting</Badge>
};

/** Changes grouped by area. Each entry expands into its field diff; actions are optional (History is read-only). */
export function DiffGroups({ busy, entries, onDiscard }: { busy?: boolean; entries: readonly DiffEntry[]; onDiscard?: (entry: DiffEntry) => void }) {
  const [open, setOpen] = useState<string>();
  return (
    <div className="lw-entry-groups">
      {GROUP_ORDER.map((group) => {
        const inGroup = entries.filter((entry) => entry.group === group);
        if (!inGroup.length) return null;
        return (
          <section aria-label={GROUP_LABEL[group]} className="lw-entry-group" key={group}>
            <h3 className="lw-entry-group__title">{GROUP_LABEL[group]} <span className="lw-entry-group__count">{inGroup.length}</span></h3>
            <ul className="lw-entry-list">
              {inGroup.map((entry) => {
                const target = editTarget(entry);
                const expanded = open === entry.key;
                return (
                  <li className="lw-entry" key={entry.key}>
                    <div className="lw-entry__head">
                      <button aria-expanded={expanded} className="lw-entry__summary" disabled={!entry.fields.length} onClick={() => setOpen(expanded ? undefined : entry.key)} type="button">
                        <Icon name={expanded ? "chevronDown" : "chevronRight"} size={16} />
                        {STATE_BADGE[entry.state]}
                        <span className="lw-entry__text"><span className="lw-entry__name">{entry.id}</span><span className="lw-entry__line">{entry.label} · {entry.summary}</span></span>
                      </button>
                      {onDiscard ? (
                        <span className="lw-row lw-row--tight">
                          <Link className={buttonClass({ size: "sm", variant: "ghost" })} search={(previous) => ({ application: previous.application, environment: previous.environment, organization: previous.organization, ...target.search })} to={target.to}>Edit</Link>
                          <Button disabled={busy} onClick={() => onDiscard(entry)} size="sm" variant="ghost">{entry.state === "removing" ? "Undo Delete" : "Discard"}</Button>
                        </span>
                      ) : null}
                    </div>
                    {expanded ? <div className="lw-entry__body"><div className="lw-fdiff">{entry.fields.map((field, index) => <FieldDiff field={field} key={`${field.path}-${index}`} />)}</div></div> : null}
                  </li>
                );
              })}
            </ul>
          </section>
        );
      })}
    </div>
  );
}

/**
 * Sample requests run on live and on the draft through the server's simulator, for each affected feature. Only
 * results that change are listed. The sample people are examples, not taken from traffic.
 */
export function SpotChecks({ draftID, features, liveID }: { draftID: string; features: readonly string[]; liveID: string }) {
  const shown = features.slice(0, 4);
  const size = SIZE_PRESETS[0]!.size;
  const cases = shown.flatMap((feature) => SAMPLE_PEOPLE.map((person) => ({ feature, person })));
  const runs = useQueries({
    queries: cases.flatMap(({ feature, person }) => [liveID, draftID].map((revision) => ({
      queryFn: () => simulate(revision, { authenticated: true, claims: person.claims, feature, platform: person.platform, size, streaming: false, trustLevel: person.trust }),
      queryKey: ["simulate", revision, feature, person.label],
      retry: false,
      staleTime: 60_000
    })))
  });
  if (!shown.length) return <p className="lw-secondary lw-note">No feature behaviour changes, so there's nothing to spot-check.</p>;
  if (runs.some((run) => run.isPending)) return <p className="lw-note" role="status">Running {runs.length} sample requests on live and on the draft…</p>;
  const rows = cases.map((item, index) => {
    const live = runs[index * 2];
    const next = runs[index * 2 + 1];
    return { ...item, after: outcomeText(next?.data, next?.error), before: outcomeText(live?.data, live?.error) };
  });
  const changed = rows.filter((row) => row.before !== row.after);
  return (
    <div className="lw-stack lw-stack--tight">
      {changed.length ? (
        <ul className="lw-effects">
          {changed.map((row) => (
            <li className={`lw-effect${row.after.startsWith("Denied") || row.after.startsWith("Not available") ? " lw-effect--danger" : " lw-effect--warning"}`} key={`${row.feature}/${row.person.label}`}>
              <Icon name="users" size={16} />
              <span><span className="lw-mono lw-mono--sm">{row.feature}</span> · {row.person.label}: <span className="lw-spot__old">{row.before}</span> → <span className="lw-spot__new">{row.after}</span></span>
            </li>
          ))}
        </ul>
      ) : <p className="lw-note">All {rows.length} sample requests get the same result.</p>}
      <p className="lw-secondary lw-note">Sample people (free and premium plan claims, iOS, Android and web) are examples, not your traffic.{features.length > shown.length ? ` Checked the first ${shown.length} of ${features.length} affected features.` : ""}</p>
    </div>
  );
}
