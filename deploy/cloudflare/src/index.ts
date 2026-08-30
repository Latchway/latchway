import { LatchwayContainer } from "./container";
import { evidenceIdentifier } from "./evidence";

export { LatchwayContainer };

const PLATFORM_HEALTH_PATH = "/__latchway/cloudflare/healthz";
const EVIDENCE_MIGRATION_PATH = "/__latchway/cloudflare/evidence/migration";
const EVIDENCE_SHUTDOWN_PATH = "/__latchway/cloudflare/evidence/shutdown";
const MAX_CONFIGURED_INSTANCES = 4;

type EvidenceContainerStub = DurableObjectStub<LatchwayContainer>;

async function authorizedEvidenceRequest(request: Request, env: Env): Promise<boolean> {
  const expected = Reflect.get(env, "LATCHWAY_EVIDENCE_TOKEN");
  const authorization = request.headers.get("Authorization");
  if (
    typeof expected !== "string" ||
    expected.length < 32 ||
    expected.length > 256 ||
    authorization === null ||
    authorization.length > 263 ||
    !authorization.startsWith("Bearer ")
  ) {
    return false;
  }
  const encoder = new TextEncoder();
  const [expectedDigest, providedDigest] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
    crypto.subtle.digest("SHA-256", encoder.encode(authorization.slice(7))),
  ]);
  return crypto.subtle.timingSafeEqual(expectedDigest, providedDigest);
}

function evidenceJSON(value: unknown, status = 200): Response {
  return Response.json(value, {
    status,
    headers: { "Cache-Control": "no-store" },
  });
}

function instanceCount(configured: string): number {
  const count = Number(configured);
  if (!Number.isSafeInteger(count) || count < 1 || count > MAX_CONFIGURED_INSTANCES) {
    throw new Error("invalid LATCHWAY_CONTAINER_INSTANCES configuration");
  }
  return count;
}

function chooseInstance(count: number): number {
  const value = new Uint32Array(1);
  crypto.getRandomValues(value);
  return value[0]! % count;
}

function pathClass(pathname: string): string {
  if (pathname === PLATFORM_HEALTH_PATH) return "platform_health";
  if (pathname === "/healthz") return "liveness";
  if (pathname === "/readyz") return "readiness";
  if (pathname.startsWith("/client/")) return "client_api";
  if (pathname.startsWith("/admin/")) return "admin_api";
  if (pathname.startsWith("/proxy/") || pathname.startsWith("/v1/")) {
    return "data_plane";
  }
  return "other";
}

function methodClass(method: string): string {
  switch (method) {
    case "GET":
    case "HEAD":
    case "POST":
    case "PUT":
    case "PATCH":
    case "DELETE":
    case "OPTIONS":
      return method;
    default:
      return "OTHER";
  }
}

function unavailable(): Response {
  return new Response(
    JSON.stringify({
      type: "about:blank",
      title: "Service unavailable",
      status: 503,
      code: "server_not_ready",
      detail: "The Latchway container is not ready.",
    }),
    {
      status: 503,
      headers: {
        "Content-Type": "application/problem+json",
        "Cache-Control": "no-store",
        "Retry-After": "1",
      },
    },
  );
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === PLATFORM_HEALTH_PATH) {
      if (request.method !== "GET" && request.method !== "HEAD") {
        return new Response(null, {
          status: 405,
          headers: { Allow: "GET, HEAD" },
        });
      }
      return Response.json({ status: "ok", platform: "cloudflare-containers" });
    }

    if (url.pathname === EVIDENCE_MIGRATION_PATH || url.pathname === EVIDENCE_SHUTDOWN_PATH) {
      if (request.method !== "POST") {
        return new Response(null, { status: 405, headers: { Allow: "POST" } });
      }
      if (!(await authorizedEvidenceRequest(request, env))) {
        return evidenceJSON({ error: "unauthorized" }, 401);
      }
      try {
        const evidenceId = await evidenceIdentifier(request);
        const container = env.LATCHWAY_CONTAINER.getByName(
          "instance-0",
        ) as EvidenceContainerStub;
        const result =
          url.pathname === EVIDENCE_MIGRATION_PATH
            ? await container.evidenceMigrationStatus(evidenceId)
            : await container.evidenceGracefulStop(evidenceId);
        return evidenceJSON(result);
      } catch (error) {
        console.error(
          JSON.stringify({
            level: "error",
            message: "Cloudflare evidence operation failed",
            operation:
              url.pathname === EVIDENCE_MIGRATION_PATH ? "migration" : "shutdown",
            error_type: error instanceof Error ? error.name : "unknown",
          }),
        );
        return evidenceJSON({ error: "evidence_operation_failed" }, 500);
      }
    }

    try {
      const count = instanceCount(env.LATCHWAY_CONTAINER_INSTANCES);
      const index = chooseInstance(count);
      const container = env.LATCHWAY_CONTAINER.getByName(`instance-${index}`);

      // Returning the original body preserves SSE and other streaming
      // responses. The Container helper starts the instance and waits for its
      // configured port without buffering either direction.
      return await container.fetch(request);
    } catch (error) {
      console.error(
        JSON.stringify({
          level: "error",
          message: "Latchway container request failed",
          path_class: pathClass(url.pathname),
          method: methodClass(request.method),
          error_type: error instanceof Error ? error.name : "unknown",
        }),
      );
      return unavailable();
    }
  },

  // One all-role instance must remain active even during a quiet traffic
  // period so signing-key rotation, reservation recovery, retention, and
  // shared JWKS refresh continue to run. The scheduled health request also
  // renews the Container activity timer without exposing a public bypass.
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    const container = env.LATCHWAY_CONTAINER.getByName("instance-0");
    const response = await container.fetch(
      new Request("http://latchway-container/healthz", { method: "GET" }),
    );
    try {
      if (!response.ok) {
        throw new Error("scheduled Latchway container health check failed");
      }
    } finally {
      await response.body?.cancel();
    }
  },
} satisfies ExportedHandler<Env>;
