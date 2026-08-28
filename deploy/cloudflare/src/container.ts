import { Container } from "@cloudflare/containers";
import type { StopParams } from "@cloudflare/containers";

const CONTAINER_PORT = 8080;

function runtimeEnvironment(env: Env): Record<string, string> {
  const values: Record<string, string> = {
    PORT: String(CONTAINER_PORT),
    LATCHWAY_DATABASE_URL: env.LATCHWAY_DATABASE_URL,
    LATCHWAY_MASTER_KEY: env.LATCHWAY_MASTER_KEY,
    LATCHWAY_PUBLIC_ORIGIN: env.LATCHWAY_PUBLIC_ORIGIN,
    LATCHWAY_ROLE: env.LATCHWAY_ROLE,
    LATCHWAY_LOG_LEVEL: env.LATCHWAY_LOG_LEVEL,
    LATCHWAY_MIGRATE_ON_START: env.LATCHWAY_MIGRATE_ON_START,
    LATCHWAY_DB_MAX_CONNECTIONS: env.LATCHWAY_DB_MAX_CONNECTIONS,
    LATCHWAY_SHUTDOWN_TIMEOUT: env.LATCHWAY_SHUTDOWN_TIMEOUT,
  };

  // The bootstrap token is deliberately removable after the first admin is
  // created. A missing secret must not become the string "undefined".
  if (
    typeof env.LATCHWAY_ADMIN_BOOTSTRAP_TOKEN === "string" &&
    env.LATCHWAY_ADMIN_BOOTSTRAP_TOKEN.length > 0
  ) {
    values.LATCHWAY_ADMIN_BOOTSTRAP_TOKEN =
      env.LATCHWAY_ADMIN_BOOTSTRAP_TOKEN;
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
}
