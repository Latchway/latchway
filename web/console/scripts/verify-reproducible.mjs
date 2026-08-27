import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const checksumPath = path.join(projectRoot, "dist", "SHA256SUMS");

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: projectRoot,
    encoding: "utf8",
    stdio: "inherit"
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with status ${result.status}`);
  }
}

function buildOnce() {
  run("pnpm", ["exec", "vite", "build"]);
  run(process.execPath, [path.join(projectRoot, "scripts", "verify-dist.mjs")]);
}

buildOnce();
const first = await readFile(checksumPath, "utf8");
buildOnce();
const second = await readFile(checksumPath, "utf8");

if (first !== second) {
  throw new Error("Two clean Vite builds produced different asset checksums.");
}

console.log("Two consecutive console builds produced identical checksums.");
