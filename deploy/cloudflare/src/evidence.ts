const MAX_EVIDENCE_BODY_BYTES = 1024;
const EVIDENCE_ID = /^[1-9][0-9]{0,19}-[1-9][0-9]{0,3}$/;

function declaredBodyLength(request: Request): number | undefined {
  const header = request.headers.get("Content-Length");
  if (header === null) {
    return undefined;
  }
  if (!/^(?:0|[1-9][0-9]*)$/.test(header)) {
    throw new Error("invalid evidence request length");
  }
  const value = Number(header);
  if (!Number.isSafeInteger(value) || value > MAX_EVIDENCE_BODY_BYTES) {
    throw new Error("invalid evidence request length");
  }
  return value;
}

async function boundedRequestBody(request: Request): Promise<Uint8Array> {
  declaredBodyLength(request);
  if (request.body === null) {
    return new Uint8Array();
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      total += value.byteLength;
      if (total > MAX_EVIDENCE_BODY_BYTES) {
        try {
          await reader.cancel("evidence request exceeded its bound");
        } catch {
          // The size violation remains authoritative even if cancellation races
          // with a peer that has already closed or errored the request stream.
        }
        throw new Error("evidence request exceeded its bound");
      }
      if (value.byteLength > 0) {
        chunks.push(value);
      }
    }
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

export async function evidenceIdentifier(request: Request): Promise<string> {
  const encoded = await boundedRequestBody(request);
  const body = new TextDecoder("utf-8", {
    fatal: true,
    ignoreBOM: false,
  }).decode(encoded);
  const value: unknown = JSON.parse(body);
  const evidenceId =
    typeof value === "object" && value !== null
      ? Reflect.get(value, "evidence_id")
      : undefined;
  if (typeof evidenceId !== "string" || !EVIDENCE_ID.test(evidenceId)) {
    throw new Error("invalid evidence identifier");
  }
  return evidenceId;
}
