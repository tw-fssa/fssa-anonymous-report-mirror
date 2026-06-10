import { mkdir, readFile, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import path from "node:path";

const SOURCE = process.env.SOURCE_API || "https://report.fssakh.org";
const PAGE_LIMIT = 500;
const ALGORITHM = "rfc6962";
const SERVICE = "fssa-anonymous-report";
const FORBIDDEN_KEYS = new Set([
  "commit",
  "commit_ref",
  "email",
  "created_by",
  "private_key",
  "secret",
  "token",
]);

function padIndex(value) {
  return String(value).padStart(9, "0");
}

function stableStringify(value) {
  return `${JSON.stringify(sortValue(value), null, 2)}\n`;
}

function sortValue(value) {
  if (Array.isArray(value)) return value.map(sortValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([key, child]) => [key, sortValue(child)])
  );
}

async function writeJson(filePath, value) {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(filePath, stableStringify(value));
}

async function readJsonIfExists(filePath) {
  if (!existsSync(filePath)) return null;
  return JSON.parse(await readFile(filePath, "utf8"));
}

async function getJson(route) {
  const url = new URL(route, SOURCE);
  const response = await fetch(url, {
    headers: {
      accept: "application/json",
      "user-agent": "tw-fssa-public-mirror/0.2",
    },
  });
  if (!response.ok) {
    const body = await response.text();
    throw new Error(`GET ${url} failed: ${response.status} ${body.slice(0, 500)}`);
  }
  return response.json();
}

function assertMirrorSafe(value, location = "$") {
  if (Array.isArray(value)) {
    value.forEach((child, index) => assertMirrorSafe(child, `${location}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.has(key)) {
      throw new Error(`Refusing to mirror forbidden key ${location}.${key}`);
    }
    assertMirrorSafe(child, `${location}.${key}`);
  }
}

async function fetchEntries(treeSize) {
  const entries = [];
  for (let from = 1; from <= treeSize;) {
    const to = Math.min(treeSize, from + PAGE_LIMIT - 1);
    const page = await getJson(`/log/entries?from=${from}&to=${to}&limit=${PAGE_LIMIT}`);
    if (!Array.isArray(page.entries)) {
      throw new Error("/log/entries response did not include an entries array");
    }
    entries.push(...page.entries);
    from = to + 1;
  }
  return entries;
}

function assertContiguous(entries, treeSize) {
  if (entries.length !== treeSize) {
    throw new Error(`Expected ${treeSize} entries, got ${entries.length}`);
  }
  for (let i = 0; i < entries.length; i += 1) {
    const expected = i + 1;
    if (entries[i].idx !== expected) {
      throw new Error(`Expected entry idx ${expected}, got ${entries[i].idx}`);
    }
  }
}

async function main() {
  const syncedAt = new Date().toISOString();
  const syncDate = syncedAt.slice(0, 10);
  const previousManifest = await readJsonIfExists("manifest.json");

  const size = await getJson("/log/size");
  const treeSize = Number(size.tree_size || 0);
  if (!Number.isInteger(treeSize) || treeSize < 0) {
    throw new Error(`Invalid tree_size: ${size.tree_size}`);
  }

  const stats = await getJson("/log/stats");
  const root = await getJson(treeSize > 0 ? `/log/root?size=${treeSize}` : "/log/root");
  const entries = await fetchEntries(treeSize);
  assertContiguous(entries, treeSize);

  const keysResponse = await getJson("/log/keys");

  const objectsToCheck = [size, stats, root, keysResponse, ...entries];
  objectsToCheck.forEach((object, index) => assertMirrorSafe(object, `public_response_${index}`));

  for (const entry of entries) {
    await writeJson(`entries/${padIndex(entry.idx)}.json`, entry);
  }

  const previousTreeSize = Number(previousManifest?.tree_size || 0);
  const consistencyFrom =
    previousTreeSize > 0 && previousTreeSize <= treeSize ? previousTreeSize : treeSize > 0 ? 1 : 0;
  let consistency = null;
  if (consistencyFrom > 0 && treeSize > 0) {
    consistency = await getJson(`/log/consistency?from=${consistencyFrom}&to=${treeSize}`);
    assertMirrorSafe(consistency, "consistency");
    await writeJson(
      `proofs/consistency/${padIndex(consistencyFrom)}-to-${padIndex(treeSize)}.json`,
      consistency
    );
  }

  const publicKeys = Array.isArray(keysResponse.keys) ? keysResponse.keys : [];
  const keysDoc = {
    service: SERVICE,
    source: SOURCE,
    privacy: "public-redacted",
    synced_at: syncedAt,
    year: Number(syncDate.slice(0, 4)),
    keys: publicKeys,
  };

  const manifest = {
    service: SERVICE,
    source: SOURCE,
    algorithm: ALGORITHM,
    privacy: "public-redacted",
    last_synced_at: syncedAt,
    tree_size: treeSize,
    root_hash: root.root_hash,
  };

  const snapshot = {
    service: SERVICE,
    source: SOURCE,
    algorithm: ALGORITHM,
    privacy: "public-redacted",
    synced_at: syncedAt,
    size,
    stats,
    root,
    consistency,
    keys: publicKeys,
    entries: {
      count: entries.length,
      first_idx: entries[0]?.idx || null,
      last_idx: entries.at(-1)?.idx || null,
    },
  };

  await writeJson("manifest.json", manifest);
  await writeJson("roots/latest.json", root);
  await writeJson(`roots/${syncDate}.json`, root);
  await writeJson("keys/latest.json", keysDoc);
  await writeJson(`keys/${keysDoc.year}.json`, keysDoc);
  await writeJson("snapshots/latest.json", snapshot);

  console.log(`Mirrored ${treeSize} public log entries and ${publicKeys.length} public keys from ${SOURCE}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
