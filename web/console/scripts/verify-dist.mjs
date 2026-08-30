import { createHash } from "node:crypto";
import { readdir, readFile, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const distRoot = path.join(projectRoot, "dist");
const checksumFile = "SHA256SUMS";

async function filesBelow(directory, prefix = "") {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const relativePath = path.posix.join(prefix, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await filesBelow(path.join(directory, entry.name), relativePath)));
    } else if (entry.isFile()) {
      files.push(relativePath);
    }
  }
  return files;
}

async function requireFile(relativePath) {
  const fullPath = path.join(distRoot, relativePath);
  const info = await stat(fullPath);
  if (!info.isFile() || info.size === 0) {
    throw new Error(`Expected a non-empty build file: ${relativePath}`);
  }
  return readFile(fullPath);
}

const index = (await requireFile("index.html")).toString("utf8");
const manifest = JSON.parse((await requireFile("manifest.json")).toString("utf8"));
const manifestEntries = Object.values(manifest);
const entry = manifestEntries.find(
  (value) => value && typeof value === "object" && value.isEntry === true
);

if (!entry || typeof entry.file !== "string") {
  throw new Error("Vite manifest does not contain an entry module.");
}
if (!index.includes("./assets/")) {
  throw new Error("Built index must use relative asset URLs for prefix-safe embedding.");
}
if (!/^assets\/.+-[A-Za-z0-9_-]{8,}\.js$/.test(entry.file)) {
  throw new Error(`Entry module is not content-addressed: ${entry.file}`);
}

await requireFile(entry.file);
const files = (await filesBelow(distRoot)).filter((file) => file !== checksumFile);
for (const file of files) {
  const contents = await readFile(path.join(distRoot, file));
  const text = contents.toString("utf8");
  if (text.includes(projectRoot) || /\/(?:Users|home)\/[^/]+\//.test(text)) {
    throw new Error(`Build output leaks a local absolute path: ${file}`);
  }
  if (file.endsWith(".map")) {
    throw new Error(`Source maps must not ship in the embedded console: ${file}`);
  }
}

const checksums = [];
for (const file of files.sort()) {
  const contents = await readFile(path.join(distRoot, file));
  checksums.push(`${createHash("sha256").update(contents).digest("hex")}  ${file}`);
}
await writeFile(path.join(distRoot, checksumFile), `${checksums.join("\n")}\n`, "utf8");

console.log(`Verified ${files.length} deterministic console assets.`);
