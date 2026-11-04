/*
 * verify-devtools-excluded.mjs
 *
 * Fails the production build if the developer dock module, its build marker,
 * or its chunk name appears in dist. The dock is behind import.meta.env.DEV;
 * this gate proves the constant-folded branch stayed out of the bundle.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const distDir = fileURLToPath(new URL("../dist", import.meta.url));
const marker = "__VERTHYS_DEV_DOCK__";
const forbiddenText = [
  marker,
  "DevDock",
  "verthys:devfixture-fill",
  "FixturePanel",
  "fixture-panel",
];
const textExtensions = new Set([".js", ".mjs", ".cjs", ".css", ".html", ".json", ".map"]);
const failures = [];

function walk(dir) {
  for (const name of readdirSync(dir)) {
    const path = join(dir, name);
    const stats = statSync(path);
    if (stats.isDirectory()) {
      walk(path);
      continue;
    }
    if (/DevDock|FixturePanel|fixture-panel/i.test(name)) {
      failures.push(`unexpected dock file: ${path}`);
    }
    if (!textExtensions.has(extname(name).toLowerCase())) continue;
    const text = readFileSync(path, "utf8");
    if (forbiddenText.some((needle) => text.includes(needle))) {
      failures.push(`unexpected dock marker: ${path}`);
    }
  }
}

walk(distDir);

if (failures.length > 0) {
  console.error("[devtools-exclusion] FAILED");
  for (const failure of failures) console.error(`  ${failure}`);
  process.exit(1);
}

console.log("[devtools-exclusion] PASS: production bundle contains no developer dock");
