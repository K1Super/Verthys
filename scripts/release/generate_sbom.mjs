// generate_sbom.mjs
// Generate a CycloneDX 1.5 SBOM from Cargo.lock, package-lock.json and
// vendored native dependency metadata. Deterministic ordering.
import fs from "node:fs";
import path from "node:path";
import { randomUUID } from "node:crypto";

const root = process.argv[2];
if (!root) {
  console.error("[sbom] project root is required");
  process.exit(1);
}

const version = fs.readFileSync(path.join(root, "VERSION"), "utf8").trim();
const components = new Map();

function add(type, name, ver, purl, scope) {
  if (!name || !ver) return;
  const key = `${name}@${ver}`;
  if (components.has(key)) return;
  components.set(key, { type, name, version: ver, purl, scope });
}

function parseCargoLock(file) {
  if (!fs.existsSync(file)) return;
  const text = fs.readFileSync(file, "utf8");
  const blocks = text.split(/^\[\[package\]\]\s*$/m).slice(1);
  for (const block of blocks) {
    const name = block.match(/^name = "([^"]+)"/m)?.[1];
    const ver = block.match(/^version = "([^"]+)"/m)?.[1];
    if (!name || !ver) continue;
    add(
      "library",
      name,
      ver,
      `pkg:cargo/${encodeURIComponent(name)}@${encodeURIComponent(ver)}`,
      "required",
    );
  }
}

parseCargoLock(path.join(root, "verthys-tauri", "src-tauri", "Cargo.lock"));
parseCargoLock(path.join(root, "verthys-tauri", "verthys-worker", "Cargo.lock"));

/**
 * npm purl：scope 与包名分别编码，保留 `@scope/name` 的层级分隔符。
 * encodeURIComponent("@scope/name") 会把斜杠编码成 %2F，生成非规范 purl。
 */
function npmPurl(name, version) {
  const slash = name.indexOf("/");
  const encoded =
    name.startsWith("@") && slash > 0
      ? `${encodeURIComponent(name.slice(0, slash))}/${encodeURIComponent(name.slice(slash + 1))}`
      : encodeURIComponent(name);
  return `pkg:npm/${encoded}@${encodeURIComponent(version)}`;
}

const npmLock = path.join(root, "verthys-tauri", "package-lock.json");
if (fs.existsSync(npmLock)) {
  const data = JSON.parse(fs.readFileSync(npmLock, "utf8"));
  for (const [key, pkg] of Object.entries(data.packages ?? {})) {
    if (!key.startsWith("node_modules/") || !pkg?.version) continue;
    const marker = "node_modules/";
    const name = pkg.name || key.slice(key.lastIndexOf(marker) + marker.length);
    const scope = pkg.dev ? "excluded" : pkg.optional ? "optional" : "required";
    add("library", name, pkg.version, npmPurl(name, pkg.version), scope);
  }
}

add(
  "application",
  "verthys-core",
  version,
  `pkg:generic/verthys-core@${version}`,
  "required",
);
add("library", "libsodium", "1.0.20", "pkg:github/jedisct1/libsodium@1.0.20", "required");
add(
  "library",
  "flatcc",
  "a2515daa948c1ae42ba95b3a904363169dff147c",
  "pkg:github/dvidelabs/flatcc@a2515daa948c1ae42ba95b3a904363169dff147c",
  "required",
);
add("library", "xxhash", "0.8.3", "pkg:github/Cyan4973/xxHash@v0.8.3", "required");

const sorted = [...components.values()].sort((a, b) =>
  a.name === b.name ? a.version.localeCompare(b.version) : a.name.localeCompare(b.name),
);

const bom = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    tools: [{ vendor: "Verthys", name: "generate_sbom.mjs", version: "1.0" }],
    component: { type: "application", name: "verthys", version },
  },
  components: sorted,
};

const outDir = path.join(root, "build");
fs.mkdirSync(outDir, { recursive: true });
const outPath = path.join(outDir, "sbom.cdx.json");
fs.writeFileSync(outPath, `${JSON.stringify(bom, null, 2)}\n`, "utf8");
console.log(`[sbom] generated ${outPath} (${sorted.length} components)`);
