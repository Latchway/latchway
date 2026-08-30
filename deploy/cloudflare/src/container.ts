import { Container } from "@cloudflare/containers";
import type { StopParams } from "@cloudflare/containers";

const CONTAINER_PORT = 8080;
const MAX_EVIDENCE_OUTPUT_BYTES = 64 * 1024;
const EVIDENCE_COMMAND_TIMEOUT_MS = 30_000;
const EVIDENCE_ID = /^[1-9][0-9]{0,19}-[1-9][0-9]{0,3}$/;

type EvidenceStopRecord = {
  evidence_id: string;
  requested_at: string;
  stopped_at: string;
  signal: "SIGTERM";
  reason: StopParams["reason"];
  exit_code: number;
};

function requiredString(env: Env, name: keyof Env): string {
  const value = Reflect.get(env, name);
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`missing required container setting: ${String(name)}`);
  }
  return value;
}

function runtimeEnvironment(env: Env): Record<string, string> {
  const values: Record<string, string> = {
    PORT: String(CONTAINER_PORT),
    LATCHWAY_DATABASE_URL: requiredString(env, "LATCHWAY_DATABASE_URL"),
    LATCHWAY_MASTER_KEY: requiredString(env, "LATCHWAY_MASTER_KEY"),
    LATCHWAY_PUBLIC_ORIGIN: requiredString(env, "LATCHWAY_PUBLIC_ORIGIN"),
    LATCHWAY_ROLE: requiredString(env, "LATCHWAY_ROLE"),
    LATCHWAY_LOG_LEVEL: requiredString(env, "LATCHWAY_LOG_LEVEL"),
    LATCHWAY_MIGRATE_ON_START: requiredString(
      env,
      "LATCHWAY_MIGRATE_ON_START",
    ),
    LATCHWAY_DB_MAX_CONNECTIONS: requiredString(
      env,
      "LATCHWAY_DB_MAX_CONNECTIONS",
    ),
    LATCHWAY_SHUTDOWN_TIMEOUT: requiredString(
      env,
      "LATCHWAY_SHUTDOWN_TIMEOUT",
    ),
  };

  // The bootstrap token is deliberately removable after the first admin is
  // created. Reflective access keeps the source valid after its optional
  // declaration is removed from wrangler.jsonc and types are regenerated.
  const bootstrapToken = Reflect.get(env, "LATCHWAY_ADMIN_BOOTSTRAP_TOKEN");
  if (typeof bootstrapToken === "string" && bootstrapToken.length > 0) {
    values.LATCHWAY_ADMIN_BOOTSTRAP_TOKEN = bootstrapToken;
  }
  return values;
}

export class LatchwayContainer extends Container<Env> {
  defaultPort = CONTAINER_PORT;
  requiredPorts = [CONTAINER_PORT];
  sleepAfter = "10m";
  enableInternet = true;
  envVars = runtimeEnvironment(this.env);

  async evidenceMigrationStatus(evidenceId: string): Promise<{
    evidence_id: string;
    command: string[];
    exit_code: number;
    status: unknown;
  }> {
    if (!EVIDENCE_ID.test(evidenceId)) {
      throw new Error("invalid evidence identifier");
    }
    await this.startAndWaitForPorts([CONTAINER_PORT], {
      portReadyTimeoutMS: EVIDENCE_COMMAND_TIMEOUT_MS,
    });
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), EVIDENCE_COMMAND_TIMEOUT_MS);
    const command = ["/latchway", "--output", "json", "migrate", "status"];
    try {
      const process = await this.ctx.container!.exec(command, {
        env: this.envVars,
        signal: controller.signal,
        stdout: "pipe",
        stderr: "pipe",
      });
      const output = await process.output();
      if (
        output.stdout.byteLength > MAX_EVIDENCE_OUTPUT_BYTES ||
        output.stderr.byteLength > MAX_EVIDENCE_OUTPUT_BYTES
      ) {
        throw new Error("migration evidence output exceeded its bound");
      }
      const stdout = new TextDecoder("utf-8", {
        fatal: true,
        ignoreBOM: false,
      }).decode(output.stdout);
      const status: unknown = JSON.parse(stdout);
      return {
        evidence_id: evidenceId,
        command,
        exit_code: output.exitCode,
        status,
      };
    } finally {
      clearTimeout(timer);
    }
  }

  async evidenceGracefulStop(evidenceId: string): Promise<{
    evidence_id: string;
    before: Awaited<ReturnType<Container<Env>["getState"]>>;
    stop: EvidenceStopRecord;
  }> {
    if (!EVIDENCE_ID.test(evidenceId)) {
      throw new Error("invalid evidence identifier");
    }
    const pendingKey = "latchway:evidence:pending-stop";
    const resultKey = `latchway:evidence:stop:${evidenceId}`;
    const pending = await this.ctx.storage.get<{ requested_at?: unknown }>(pendingKey);
    if (pending !== undefined) {
      const requestedAt =
        typeof pending.requested_at === "string"
          ? Date.parse(pending.requested_at)
          : Number.NaN;
      if (!Number.isFinite(requestedAt) || Date.now() - requestedAt < 15 * 60_000) {
        throw new Error("another evidence stop is already pending");
      }
      await this.ctx.storage.delete(pendingKey);
    }
    const before = await this.getState();
    if (before.status !== "healthy" && before.status !== "running") {
      throw new Error("container is not running");
    }
    await this.ctx.storage.put(pendingKey, {
      evidence_id: evidenceId,
      requested_at: new Date().toISOString(),
    });
    await this.ctx.storage.delete(resultKey);
    await this.stop("SIGTERM");
    const stop = await this.ctx.storage.get<EvidenceStopRecord>(resultKey);
    if (stop === undefined || stop.evidence_id !== evidenceId) {
      throw new Error("container stop result was not recorded");
    }
    return { evidence_id: evidenceId, before, stop };
  }

  onStart(): void {
    console.log(
      JSON.stringify({
        level: "info",
        message: "Latchway container started",
        container_class: "LatchwayContainer",
      }),
    );
  }

  async onStop(params: StopParams): Promise<void> {
    const pendingKey = "latchway:evidence:pending-stop";
    const pending = await this.ctx.storage.get<{
      evidence_id: string;
      requested_at: string;
    }>(pendingKey);
    if (pending !== undefined && EVIDENCE_ID.test(pending.evidence_id)) {
      const record: EvidenceStopRecord = {
        evidence_id: pending.evidence_id,
        requested_at: pending.requested_at,
        stopped_at: new Date().toISOString(),
        signal: "SIGTERM",
        reason: params.reason,
        exit_code: params.exitCode,
      };
      await this.ctx.storage.put(
        `latchway:evidence:stop:${pending.evidence_id}`,
        record,
      );
      await this.ctx.storage.delete(pendingKey);
    }
    console.log(
      JSON.stringify({
        level: "info",
        message: "Latchway container stopped",
        container_class: "LatchwayContainer",
        reason: params.reason,
        exit_code: params.exitCode,
      }),
    );
  }

  onError(error: unknown): never {
    console.error(
      JSON.stringify({
        level: "error",
        message: "Latchway container failed",
        container_class: "LatchwayContainer",
        error_type: error instanceof Error ? error.name : "unknown",
      }),
    );
    throw new Error("Latchway container failed");
  }
}
