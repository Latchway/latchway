import assert from "node:assert/strict";
import test from "node:test";

import { evidenceIdentifier } from "../src/evidence.ts";

function streamedRequest(chunks, { closeAfterChunks = true } = {}) {
  let cancelled = false;
  let index = 0;
  const body = new ReadableStream({
    pull(controller) {
      const chunk = chunks[index];
      if (chunk !== undefined) {
        controller.enqueue(chunk);
        index += 1;
      }
      if (closeAfterChunks && index === chunks.length) {
        controller.close();
      }
    },
    cancel() {
      cancelled = true;
    },
  });
  const request = new Request("https://latchway.example/evidence", {
    method: "POST",
    body,
    duplex: "half",
  });
  return { request, wasCancelled: () => cancelled };
}

test("accepts a bounded streamed body without Content-Length", async () => {
  const encoder = new TextEncoder();
  const { request } = streamedRequest([
    encoder.encode('{"evidence_'),
    encoder.encode('id":"123-4"}'),
  ]);

  assert.equal(request.headers.has("Content-Length"), false);
  assert.equal(await evidenceIdentifier(request), "123-4");
});

test("rejects and cancels an oversized chunked body without Content-Length", async () => {
  const { request, wasCancelled } = streamedRequest([
    new Uint8Array(700),
    new Uint8Array(700),
  ], { closeAfterChunks: false });

  assert.equal(request.headers.has("Content-Length"), false);
  await assert.rejects(
    evidenceIdentifier(request),
    /evidence request exceeded its bound/,
  );
  assert.equal(wasCancelled(), true);
});

test("rejects an oversized declared body before consuming its stream", async () => {
  const request = new Request("https://latchway.example/evidence", {
    method: "POST",
    headers: { "Content-Length": "1025" },
    body: new ReadableStream({
      pull(controller) {
        controller.close();
      },
    }),
    duplex: "half",
  });

  await assert.rejects(evidenceIdentifier(request), /invalid evidence request length/);
});
