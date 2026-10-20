// Verifies the mirrored transparency log offline (no network, no secrets).
//
//   node scripts/verify.mjs [base-commit]
//
// Always checks the current checkout:
// - entries/ holds exactly 1..tree_size, each file's idx matches its name, and no forbidden field is present anywhere;
// - the RFC 6962 Merkle root of the entries equals manifest.json, roots/latest.json and snapshots/latest.json;
// - every proofs/consistency/A-to-B.json is a valid RFC 9162 consistency proof between the roots of the first A and B entries.
// With a base commit (the push's "before"; defaults to HEAD~1), also checks that the log only grew since then:
// - the base manifest's root equals the root of the first base.tree_size entries now;
// - entries and proofs were only added (never modified or deleted), no mirrored data file was deleted, and no
//   roots/YYYY-MM-DD.json from before the base's sync day changed.
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync } from "node:fs";

const FORBIDDEN_KEYS = new Set(["commit", "commit_ref", "email", "created_by", "private_key", "secret", "token"]);
const DATA_DIRS = ["entries", "proofs", "roots", "keys", "snapshots"];
const failures = [];
const fail = (message) => failures.push(message);
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const pad = (n) => String(n).padStart(9, "0");

// ---- RFC 6962 / 9162 ----
const sha256 = (...parts) => createHash("sha256").update(Buffer.concat(parts)).digest();
const leafHash = (hex) => sha256(Buffer.of(0), Buffer.from(hex, "hex"));
const nodeHash = (left, right) => sha256(Buffer.of(1), left, right);

// Root of every prefix size, computed in one pass: roots[n] = MTH(first n leaves).
function prefixRoots(leaves) {
  const roots = [sha256().toString("hex")];
  const stack = []; // perfect subtrees [{size, hash}], largest first
  for (const leaf of leaves) {
    let item = { size: 1, hash: leafHash(leaf) };
    while (stack.length && stack.at(-1).size === item.size) {
      const left = stack.pop();
      item = { size: left.size * 2, hash: nodeHash(left.hash, item.hash) };
    }
    stack.push(item);
    // MTH folds the perfect subtrees from the right.
    let hash = stack.at(-1).hash;
    for (let i = stack.length - 2; i >= 0; i--) hash = nodeHash(stack[i].hash, hash);
    roots.push(hash.toString("hex"));
  }
  return roots;
}

function verifyConsistency(first, second, firstRoot, secondRoot, proof) {
  if (!Number.isInteger(first) || !Number.isInteger(second) || first < 1 || first > second) return false;
  if (!Array.isArray(proof) || !proof.every((h) => /^[0-9a-f]{64}$/.test(h))) return false;
  if (first === second) return proof.length === 0 && firstRoot === secondRoot;
  const path = proof.map((h) => Buffer.from(h, "hex"));
  if ((first & (first - 1)) === 0) path.unshift(Buffer.from(firstRoot, "hex"));
  if (!path.length) return false;
  let fn = first - 1;
  let sn = second - 1;
  while (fn & 1) { fn >>= 1; sn >>= 1; }
  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if ((fn & 1) || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      while (!(fn & 1) && fn !== 0) { fn >>= 1; sn >>= 1; }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return fr.toString("hex") === firstRoot && sr.toString("hex") === secondRoot && sn === 0;
}

function scanForbidden(value, location) {
  if (Array.isArray(value)) return value.forEach((child, i) => scanForbidden(child, `${location}[${i}]`));
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (FORBIDDEN_KEYS.has(key)) fail(`forbidden field ${location}.${key}`);
    scanForbidden(child, `${location}.${key}`);
  }
}

function listJson(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap((d) =>
    d.isDirectory() ? listJson(`${dir}/${d.name}`) : d.name.endsWith(".json") ? [`${dir}/${d.name}`] : []);
}

const git = (...args) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

// ---- current checkout ----
const manifest = readJson("manifest.json");
const treeSize = manifest.tree_size;
if (manifest.algorithm !== "rfc6962" || manifest.privacy !== "public-redacted") fail("manifest algorithm/privacy changed");
if (!Number.isInteger(treeSize) || treeSize < 0) throw new Error(`invalid manifest tree_size ${treeSize}`);

const entryFiles = readdirSync("entries").filter((n) => n.endsWith(".json")).sort();
if (entryFiles.length !== treeSize) fail(`manifest says ${treeSize} entries, entries/ has ${entryFiles.length}`);
const leaves = [];
for (let idx = 1; idx <= treeSize; idx++) {
  const path = `entries/${pad(idx)}.json`;
  if (!existsSync(path)) { fail(`missing ${path}`); continue; }
  const entry = readJson(path);
  if (entry.idx !== idx) fail(`${path} has idx ${entry.idx}`);
  if (!/^[0-9a-f]{64}$/.test(entry.leaf_hash || "")) fail(`${path} has an invalid leaf_hash`);
  leaves.push(entry.leaf_hash);
}
for (const path of ["manifest.json", ...DATA_DIRS.flatMap(listJson)]) scanForbidden(readJson(path), path);

const roots = failures.length ? [] : prefixRoots(leaves);
if (roots.length) {
  const root = roots[treeSize];
  if (manifest.root_hash !== root) fail(`manifest root_hash ${manifest.root_hash} != computed ${root}`);
  const latest = readJson("roots/latest.json");
  if (latest.root_hash !== root || latest.tree_size !== treeSize) fail("roots/latest.json does not match the entries");
  const snapshot = readJson("snapshots/latest.json");
  if (snapshot.root?.root_hash !== root || snapshot.root?.tree_size !== treeSize) fail("snapshots/latest.json does not match the entries");

  let proofs = 0;
  for (const name of existsSync("proofs/consistency") ? readdirSync("proofs/consistency") : []) {
    const match = /^(\d{9})-to-(\d{9})\.json$/.exec(name);
    if (!match) { fail(`unexpected proof file ${name}`); continue; }
    const [from, to] = [Number(match[1]), Number(match[2])];
    if (to > treeSize) { fail(`${name} is beyond tree_size ${treeSize}`); continue; }
    const p = readJson(`proofs/consistency/${name}`);
    if (p.from_tree_size !== from || p.to_tree_size !== to || p.from_root !== roots[from] || p.to_root !== roots[to]
      || !verifyConsistency(from, to, roots[from], roots[to], p.proof)) fail(`invalid consistency proof ${name}`);
    proofs++;
  }
  console.log(`tree_size ${treeSize}, root ${root}, ${proofs} consistency proofs checked`);
}

// ---- append-only since the base commit ----
let base = process.argv[2] || "";
if (!base || /^0+$/.test(base)) base = "HEAD~1";
if (!/^([0-9a-f]{40}|HEAD~1)$/.test(base)) throw new Error(`invalid base commit ${base}`);
let baseManifest = null;
try { git("cat-file", "-e", `${base}^{commit}`); baseManifest = JSON.parse(git("show", `${base}:manifest.json`)); }
catch { console.log(`no base manifest at ${base}; append-only check skipped`); }
if (baseManifest && roots.length) {
  const before = baseManifest.tree_size;
  if (!Number.isInteger(before) || before > treeSize) fail(`log shrank: ${before} -> ${treeSize}`);
  else if (before > 0 && roots[before] !== baseManifest.root_hash) fail(`root of the first ${before} entries changed: history was rewritten`);
  // Dated root files are rewritten by every sync of that day, so only days before the base's sync are frozen.
  const baseDate = String(baseManifest.last_synced_at || "").slice(0, 10);
  const dated = (path) => /^roots\/(\d{4}-\d{2}-\d{2})\.json$/.exec(path)?.[1];
  for (const line of git("diff", "--name-status", "--no-renames", base, "HEAD", "--", ...DATA_DIRS).split("\n").filter(Boolean)) {
    const [status, path] = line.split("\t");
    if (status === "A") continue;
    const rewritable = status === "M" && (/^(keys|snapshots)\//.test(path) || path === "roots/latest.json" || (baseDate !== "" && (dated(path) || "") >= baseDate));
    if (!rewritable) fail(`${path} was ${status === "D" ? "deleted" : "modified"}; mirrored entries, proofs and past roots are append-only`);
  }
  console.log(`append-only since ${base}: ${before} -> ${treeSize}`);
}

if (failures.length) {
  for (const message of failures) console.error(`::error::${message}`);
  process.exit(1);
}
console.log("mirror verified");
