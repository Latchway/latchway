import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const scriptsDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryRoot = join(scriptsDirectory, "..", "..", "..");
const script = join(scriptsDirectory, "list-applications.sh");
const accountId = "a".repeat(32);
const apiToken = `token_${"b".repeat(32)}`;

function application(identifier, name, image, health = {}) {
  return {
    id: identifier,
    name,
    image,
    instances: 1,
    version: 3,
    updated_at: "2026-09-02T01:00:00Z",
    created_at: "2026-09-02T00:00:00Z",
    health: {
      instances: {
        failed: health.failed ?? 0,
        starting: health.starting ?? 0,
        scheduling: health.scheduling ?? 0,
        active: health.active ?? 0,
      },
    },
  };
}

function page(result, nextPageToken) {
  return {
    success: true,
    errors: [],
    messages: [],
    result,
    result_info: { next_page_token: nextPageToken },
  };
}

function applicationId(index) {
  const value = index.toString(16).padStart(32, "0");
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}

async function fixture(t, pages) {
  const root = await mkdtemp(join(tmpdir(), "latchway-cloudflare-list-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const bin = join(root, "bin");
  const pageDirectory = join(root, "pages");
  const calls = join(root, "calls.txt");
  const output = join(root, "applications.json");
  await mkdir(bin);
  await mkdir(pageDirectory);
  await Promise.all(
    pages.map((contents, index) =>
      writeFile(join(pageDirectory, `page-${index + 1}.json`), `${JSON.stringify(contents)}\n`),
    ),
  );
  const fakeCurl = join(bin, "curl");
  await writeFile(
    fakeCurl,
    `#!/usr/bin/env bash
set -Eeuo pipefail
output_path=
cursor=
authorization_file=
while (( $# > 0 )); do
  case "$1" in
    --output)
      output_path="$2"
      shift 2
      ;;
    --data-urlencode)
      if [[ "$2" == page_token=* ]]; then cursor="\${2#page_token=}"; fi
      shift 2
      ;;
    --header)
      if [[ "$2" == @* ]]; then authorization_file="\${2#@}"; fi
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
test -n "$output_path"
test -f "$authorization_file"
authorization=$(sed -n 's/^Authorization: Bearer //p' "$authorization_file")
[[ "$authorization" =~ ^[A-Za-z0-9._~-]+$ ]]
(( \${#authorization} >= 20 && \${#authorization} <= 256 ))
printf '%s\n' "\${cursor:-<first>}" >> "$CALLS"
page_number=1
if [[ -n "$cursor" ]]; then
  [[ "$cursor" =~ ^cursor-([1-9][0-9]*)$ ]]
  page_number="\${BASH_REMATCH[1]}"
fi
page_path="$PAGE_DIRECTORY/page-$page_number.json"
test -f "$page_path"
install -m 0600 "$page_path" "$output_path"
`,
  );
  await chmod(fakeCurl, 0o755);
  return {
    calls,
    output,
    root,
    run() {
      return spawnSync("/bin/bash", [script, output], {
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${bin}:${process.env.PATH}`,
          CLOUDFLARE_ACCOUNT_ID: accountId,
          CLOUDFLARE_API_TOKEN: apiToken,
          PAGE_DIRECTORY: pageDirectory,
          CALLS: calls,
        },
      });
    },
  };
}

async function assertFailurePreservesOutput(state, stderrPattern) {
  const sentinel = '[{"previous":"observation"}]\n';
  await writeFile(state.output, sentinel);

  const result = state.run();
  assert.notEqual(result.status, 0);
  if (stderrPattern) assert.match(result.stderr, stderrPattern);
  assert.equal(await readFile(state.output, "utf8"), sentinel);
  return result;
}

test("follows every cursor and emits a sorted normalized application list", async (t) => {
  const firstId = "22222222-2222-2222-2222-222222222222";
  const secondId = "11111111-1111-1111-1111-111111111111";
  const mirror = `registry.cloudflare.com/${accountId}/latchway@sha256:${"c".repeat(64)}`;
  const state = await fixture(
    t,
    [
      page([application(firstId, "other", "registry.cloudflare.com/other", { failed: 1 })], "cursor-2"),
      page([application(secondId, "latchway", mirror, { active: 1 })], null),
    ],
  );

  const result = state.run();
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(await readFile(state.output, "utf8")), [
    {
      created_at: "2026-09-02T00:00:00Z",
      id: secondId,
      image: mirror,
      instances: 1,
      name: "latchway",
      state: "active",
      updated_at: "2026-09-02T01:00:00Z",
      version: 3,
    },
    {
      created_at: "2026-09-02T00:00:00Z",
      id: firstId,
      image: "registry.cloudflare.com/other",
      instances: 1,
      name: "other",
      state: "degraded",
      updated_at: "2026-09-02T01:00:00Z",
      version: 3,
    },
  ]);
  assert.equal(await readFile(state.calls, "utf8"), "<first>\ncursor-2\n");
});

test("rejects a repeated cursor without replacing an existing observation", async (t) => {
  const id = "11111111-1111-1111-1111-111111111111";
  const state = await fixture(
    t,
    [
      page([application(id, "other", "registry.cloudflare.com/other")], "cursor-2"),
      page([], "cursor-2"),
    ],
  );
  await assertFailurePreservesOutput(state, /repeated a cursor/u);
});

test("rejects duplicate application identities across provider pages", async (t) => {
  const id = "11111111-1111-1111-1111-111111111111";
  const state = await fixture(
    t,
    [
      page([application(id, "first", "registry.cloudflare.com/first")], "cursor-2"),
      page([application(id, "second", "registry.cloudflare.com/second")], null),
    ],
  );

  const result = state.run();
  assert.notEqual(result.status, 0);
  await assert.rejects(readFile(state.output), { code: "ENOENT" });
});

test("rejects a malformed provider envelope without replacing an existing observation", async (t) => {
  const state = await fixture(t, [{
    success: true,
    errors: [],
    messages: [],
    result: "not-an-application-array",
    result_info: { next_page_token: null },
  }]);

  await assertFailurePreservesOutput(state);
});

test("rejects pagination beyond 100 pages without replacing an existing observation", async (t) => {
  const pages = Array.from({ length: 100 }, (_, index) => page([], `cursor-${index + 2}`));
  const state = await fixture(t, pages);

  await assertFailurePreservesOutput(state);
  const calls = (await readFile(state.calls, "utf8")).trim().split("\n");
  assert.equal(calls.length, 100);
  assert.equal(calls.at(-1), "cursor-100");
});

test("rejects more than 5000 records without replacing an existing observation", async (t) => {
  const pages = Array.from({ length: 51 }, (_, pageIndex) => {
    const applications = Array.from({ length: 100 }, (_, rowIndex) => {
      const index = pageIndex * 100 + rowIndex + 1;
      return application(applicationId(index), `application-${index}`, `registry.cloudflare.com/application-${index}`);
    });
    return page(applications, pageIndex === 50 ? null : `cursor-${pageIndex + 2}`);
  });
  const state = await fixture(t, pages);

  await assertFailurePreservesOutput(state);
  const calls = (await readFile(state.calls, "utf8")).trim().split("\n");
  assert.equal(calls.length, 51);
});

test("rejects a provider page larger than 1 MiB without replacing an existing observation", async (t) => {
  const oversized = page([], null);
  oversized.messages = ["x".repeat(1_048_576)];
  const state = await fixture(t, [oversized]);

  await assertFailurePreservesOutput(state);
});

test("rejects normalized output larger than 8 MiB without replacing an existing observation", async (t) => {
  const largeTimestamp = "2".repeat(900_000);
  const pages = Array.from({ length: 10 }, (_, index) => {
    const record = application(
      applicationId(index + 1),
      `application-${index + 1}`,
      `registry.cloudflare.com/application-${index + 1}`,
    );
    record.updated_at = largeTimestamp;
    return page([record], index === 9 ? null : `cursor-${index + 2}`);
  });
  const state = await fixture(t, pages);

  await assertFailurePreservesOutput(state);
  const calls = (await readFile(state.calls, "utf8")).trim().split("\n");
  assert.equal(calls.length, 10);
});

test("keeps the operator helper and runbook aligned with protected evidence", async () => {
  const source = await readFile(script, "utf8");
  const workflow = await readFile(
    join(repositoryRoot, ".github", "workflows", "deployment-evidence.yml"),
    "utf8",
  );
  const runbook = await readFile(
    join(
      repositoryRoot,
      "docs",
      "public",
      "operations",
      "deploy-cloudflare-containers.mdx",
    ),
    "utf8",
  );
  for (const required of [
    "https://api.cloudflare.com/client/v4/accounts/${CLOUDFLARE_ACCOUNT_ID}/containers/dash/applications",
    "cloudflare_application_per_page=100",
    "cloudflare_application_max_pages=100",
    "cloudflare_application_max_records=5000",
    "cloudflare_application_max_page_bytes=1048576",
    "cloudflare_application_max_output_bytes=8388608",
    '--data-urlencode "page_token=$page_token"',
    ".result_info.next_page_token",
    "seen_page_token_hashes",
    "([.[].id] | length) == ([.[].id] | unique | length)",
  ]) {
    assert.equal(source.includes(required), true, required);
    assert.equal(workflow.includes(required), true, required);
  }
  assert.match(source, /--header @"\$cloudflare_api_headers"/u);
  assert.doesNotMatch(source, /--header "Authorization: Bearer \$CLOUDFLARE_API_TOKEN"/u);
  assert.match(runbook, /bash scripts\/list-applications\.sh/u);
  assert.doesNotMatch(runbook, /pnpm exec wrangler containers list --json/u);
});
