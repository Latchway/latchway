import { useNavigate } from "@tanstack/react-router";
import { type FormEvent, useState } from "react";

import { adminRequest, ClientComponentSchema } from "../../api/admin";
import { problemFromError } from "../../api/auth";
import { useWorkspace } from "../../app/workspace-context-value";
import { Input } from "../../ui";
import { GO_TO_HELP, goToRecord } from "./users-model";

/**
 * Go to ID for Users & Installs: usr_ opens the user, fam_ the installation, cmp_ the installation with that part
 * highlighted, and req_ the request. Anything else explains why there's no search.
 */
export function GoToForm({ onUser }: { onUser?: (userID: string) => void }) {
  const workspace = useWorkspace();
  const navigate = useNavigate();
  const [value, setValue] = useState("");
  const [error, setError] = useState<string>();
  const environmentID = workspace.environment?.id ?? "";
  const linkSearch = { application: workspace.search.application, environment: workspace.search.environment, organization: workspace.search.organization };
  const scope = `${workspace.application?.display_name ?? "this application"} · ${workspace.environment?.display_name ?? "this environment"}`;

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const target = goToRecord(value);
    setError(undefined);
    if (target.kind === "invalid") {
      setError(GO_TO_HELP);
      return;
    }
    if (target.kind === "user") {
      setValue("");
      if (onUser) onUser(target.id);
      else void navigate({ search: { ...linkSearch, user_id: target.id }, to: "/users" });
      return;
    }
    if (target.kind === "request") {
      setValue("");
      void navigate({ search: { ...linkSearch, request: target.id }, to: "/requests" });
      return;
    }
    if (target.kind === "family") {
      setValue("");
      void navigate({ search: { ...linkSearch, environment_id: environmentID, family_id: target.id }, to: "/installation-families" });
      return;
    }
    try {
      const component = (await adminRequest(`/admin/v1/client-components/${target.id}`, ClientComponentSchema)).data;
      if (component.id !== target.id || component.environment_id !== environmentID) {
        setError(`${target.id} belongs to a different environment than ${scope}.`);
        return;
      }
      setValue("");
      void navigate({ search: { ...linkSearch, component_id: component.id, environment_id: environmentID, family_id: component.installation_family_id }, to: "/installation-families" });
    } catch (failure) {
      const problem = problemFromError(failure);
      setError(problem.status === 404 ? `No component ${target.id} in ${scope}.` : problem.detail);
    }
  }

  return (
    <form className="lw-rq-go" onSubmit={(event) => void submit(event)} role="search">
      <Input aria-label="Go to a user, installation, component or request ID" boxClassName="lw-search" onChange={(event) => { setValue(event.target.value); setError(undefined); }} placeholder="Go to usr_, fam_, cmp_ or req_…" prefix="search" spellCheck={false} value={value} />
      {error ? <span className="lw-rq-go__err" role="status">{error}</span> : null}
    </form>
  );
}
