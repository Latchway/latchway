import { Container } from "@cloudflare/containers";
import type { StopParams } from "@cloudflare/containers";

const CONTAINER_PORT = 8080;

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

  onStart(): void {
    console.log(
      JSON.stringify({
        level: "info",
        message: "Latchway container started",
        container_class: "LatchwayContainer",
      }),
    );
  }

  onStop(params: StopParams): void {
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
