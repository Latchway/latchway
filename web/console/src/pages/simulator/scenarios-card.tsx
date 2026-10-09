import { useQuery, useQueryClient } from "@tanstack/react-query";
import { type FormEvent, useId, useState } from "react";

import { problemFromError } from "../../api/auth";
import { deleteScenario, listScenarios, saveScenario, ScenarioInputSchema, type SimulationScenario } from "../../api/policy-insights";
import { Button, Card, ConfirmDialog, Field, Input } from "../../ui";
import { ProblemNotice } from "../control-plane-pages";
import { inputFromScenario, type SimulationInput, simulationBody } from "./simulator-model";

/**
 * Saved Simulator inputs for this application, shared with the team. Claims in a scenario are test values someone
 * typed; they're stored with the scenario and never written to the audit log.
 */
export function ScenariosCard({ applicationID, canSave, input, onLoad }: { applicationID: string; canSave: boolean; input: SimulationInput; onLoad: (input: SimulationInput) => void }) {
  const queryClient = useQueryClient();
  const nameID = useId();
  const [selected, setSelected] = useState<string>("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<unknown>();
  const [message, setMessage] = useState<string>();
  const [deleting, setDeleting] = useState<SimulationScenario>();
  const scenarios = useQuery({
    queryFn: () => listScenarios(applicationID),
    queryKey: ["simulation-scenarios", applicationID],
    retry: false
  });
  const items = scenarios.data ?? [];
  const current = items.find((item) => item.id === selected);
  const trimmed = name.trim();
  const replacing = items.find((item) => item.name === trimmed);

  async function refresh(): Promise<void> {
    await queryClient.invalidateQueries({ queryKey: ["simulation-scenarios", applicationID] });
  }

  async function save(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    if (!trimmed) return;
    setBusy(true);
    setProblem(undefined);
    setMessage(undefined);
    try {
      const saved = await saveScenario(applicationID, trimmed, ScenarioInputSchema.parse(simulationBody(input)), replacing);
      setSelected(saved.id);
      setName("");
      setMessage(replacing ? `Updated ${saved.name}.` : `Saved ${saved.name}.`);
      await refresh();
    } catch (error) {
      setProblem(error);
    } finally {
      setBusy(false);
    }
  }

  async function remove(scenario: SimulationScenario): Promise<void> {
    setBusy(true);
    setProblem(undefined);
    try {
      await deleteScenario(scenario);
      setDeleting(undefined);
      setSelected("");
      setMessage(`Deleted ${scenario.name}.`);
      await refresh();
    } catch (error) {
      setProblem(error);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card icon="star" title="Saved scenarios">
      <div className="lw-stack lw-stack--tight">
        {scenarios.error ? <ProblemNotice problem={problemFromError(scenarios.error)} /> : null}
        {items.length ? (
          <div className="lw-row lw-row--wrap">
            <select aria-label="Saved scenario" className="lw-select" onChange={(event) => setSelected(event.target.value)} value={selected}>
              <option value="">Choose a scenario…</option>
              {items.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}
            </select>
            <Button disabled={!current} onClick={() => { if (current) { onLoad(inputFromScenario(current.input)); setMessage(`Loaded ${current.name}.`); } }} size="sm">Load</Button>
            {canSave ? <Button aria-label="Delete scenario" destructive disabled={!current} icon="trash" onClick={() => setDeleting(current)} size="sm" variant="ghost" /> : null}
          </div>
        ) : scenarios.isPending ? <p className="lw-page-status" role="status">Loading scenarios…</p> : <p className="lw-secondary lw-note">None yet. Save the inputs you test often, like a free user on iOS, to reuse them.</p>}
        {current ? <p className="lw-faint lw-note">{current.input.feature} · {current.input.platform} · saved by <span className="lw-mono lw-mono--sm">{current.updated_by}</span> {new Date(current.updated_at).toLocaleString()}</p> : null}
        {canSave ? (
          <form className="lw-row lw-row--wrap" onSubmit={(event) => void save(event)}>
            <Field hint={replacing ? "A scenario has this name; saving replaces its inputs." : "Saves the inputs above, including claims."} id={nameID} label="Save current inputs as">
              <Input id={nameID} maxLength={100} onChange={(event) => setName(event.target.value)} placeholder="Free user on iOS" value={name} />
            </Field>
            <Button disabled={!trimmed || !input.feature} loading={busy} type="submit">{replacing ? "Replace" : "Save"}</Button>
          </form>
        ) : null}
        {message ? <p className="lw-note" role="status">{message}</p> : null}
        {problem ? <ProblemNotice problem={problemFromError(problem)} /> : null}
      </div>
      {deleting ? (
        <ConfirmDialog confirmLabel="Delete Scenario" description="It's removed for everyone on the team. Simulations already shown aren't affected." destructive onCancel={() => setDeleting(undefined)} onConfirm={() => void remove(deleting)} pending={busy} title={`Delete ${deleting.name}?`} />
      ) : null}
    </Card>
  );
}
