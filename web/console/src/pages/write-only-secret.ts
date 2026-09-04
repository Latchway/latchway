import { adminRequest, queryPath, SecretMetadataSchema } from "../api/admin";
import { AdminRequestError } from "../api/auth";
import { SecretResourcePageSchema, type SecretResource } from "../api/resources";

export type WriteOnlySecretAction = "create" | "use_existing";

export type WriteOnlySecretResolution =
  | { metadata: SecretResource; outcome: "created" | "existing" }
  | {
    metadata: SecretResource;
    outcome: "confirmation_required";
    operationId?: string;
    reason: "already_exists" | "create_response_indeterminate";
  };

export class WriteOnlySecretResolutionError extends Error {
  readonly code: "metadata_scope_mismatch" | "not_found" | "outcome_unknown";
  readonly operationId?: string;

  constructor(
    code: WriteOnlySecretResolutionError["code"],
    message: string,
    operationId?: string
  ) {
    super(message);
    this.name = "WriteOnlySecretResolutionError";
    this.code = code;
    this.operationId = operationId;
  }
}

export async function findWriteOnlySecretMetadata(
  environmentID: string,
  name: string
): Promise<SecretResource | undefined> {
  let cursor: string | undefined;
  for (let page = 0; page < 100; page += 1) {
    const response = (await adminRequest(queryPath("/admin/v1/secrets", {
      environment_id: environmentID,
      page_size: "200",
      ...(cursor ? { cursor } : {})
    }), SecretResourcePageSchema)).data;
    if (response.items.some((item) => item.environment_id !== environmentID)) {
      throw new WriteOnlySecretResolutionError(
        "metadata_scope_mismatch",
        "The Secrets API returned metadata outside the selected environment."
      );
    }
    const matches = response.items.filter((item) => item.name === name);
    if (matches.length > 1) {
      throw new WriteOnlySecretResolutionError(
        "metadata_scope_mismatch",
        "The Secrets API returned duplicate metadata for the requested logical name."
      );
    }
    if (matches[0]) return matches[0];
    if (!response.page.has_more) return undefined;
    if (!response.page.next_cursor || response.page.next_cursor === cursor) {
      throw new WriteOnlySecretResolutionError(
        "metadata_scope_mismatch",
        "The Secrets API returned an invalid metadata cursor."
      );
    }
    cursor = response.page.next_cursor;
  }
  throw new WriteOnlySecretResolutionError(
    "metadata_scope_mismatch",
    "The Secrets API metadata search exceeded its bounded page limit."
  );
}

export async function resolveWriteOnlySecret(input: {
  action: WriteOnlySecretAction;
  environmentID: string;
  name: string;
  value?: string;
}): Promise<WriteOnlySecretResolution> {
  const existing = await findWriteOnlySecretMetadata(input.environmentID, input.name);
  if (input.action === "use_existing") {
    if (!existing) {
      throw new WriteOnlySecretResolutionError(
        "not_found",
        `No secret metadata named ${input.name} exists in the selected environment.`
      );
    }
    return { metadata: existing, outcome: "existing" };
  }
  if (existing) {
    return { metadata: existing, outcome: "confirmation_required", reason: "already_exists" };
  }
  if (!input.value) {
    throw new WriteOnlySecretResolutionError(
      "not_found",
      "Enter a new write-only secret value before storing it."
    );
  }

  try {
    const created = (await adminRequest("/admin/v1/secrets", SecretMetadataSchema, {
      body: { environment_id: input.environmentID, name: input.name, value: input.value },
      method: "POST"
    })).data;
    if (created.environment_id !== input.environmentID || created.name !== input.name) {
      throw new WriteOnlySecretResolutionError(
        "metadata_scope_mismatch",
        "The Secrets API create response did not match the requested environment and logical name."
      );
    }
    return { metadata: created, outcome: "created" };
  } catch (createError) {
    const operationId = createError instanceof AdminRequestError
      ? createError.problem.operationId
      : undefined;
    try {
      const reconciled = await findWriteOnlySecretMetadata(input.environmentID, input.name);
      if (reconciled) {
        return {
          metadata: reconciled,
          outcome: "confirmation_required",
          ...(operationId ? { operationId } : {}),
          reason: "create_response_indeterminate"
        };
      }
    } catch {
      throw new WriteOnlySecretResolutionError(
        "outcome_unknown",
        `The create result for secret ${input.name} is unknown and its metadata could not be reconciled. Retry only after metadata reads recover; the Console will check the exact name before another create.`,
        operationId
      );
    }
    throw createError;
  }
}
