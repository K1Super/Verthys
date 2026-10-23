// 校验 Rust 错误码清单与前端文案键完全一致。
//
// 任一侧新增或删除错误码而未同步另一侧，都会在 CI 中失败；防止界面出现
// 未映射错误码或映射了根本不存在的码。
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rustPath = resolve(
  root,
  "verthys-tauri",
  "src-tauri",
  "src",
  "updater",
  "error.rs",
);
const tsPath = resolve(root, "verthys-tauri", "src", "lib", "updater_error.ts");

const extract = (text) =>
  new Set(
    [...text.matchAll(/E_UPDATER_[A-Z_]+/g)].map((match) => match[0]),
  );

const rustCodes = extract(readFileSync(rustPath, "utf8"));
const tsCodes = extract(readFileSync(tsPath, "utf8"));
const missingInTs = [...rustCodes].filter((code) => !tsCodes.has(code));
const extraInTs = [...tsCodes].filter((code) => !rustCodes.has(code));

if (missingInTs.length > 0 || extraInTs.length > 0) {
  for (const code of missingInTs) {
    console.error(`[FAIL] 前端缺少错误码文案: ${code}`);
  }
  for (const code of extraInTs) {
    console.error(`[FAIL] 前端存在未登记错误码: ${code}`);
  }
  process.exit(1);
}

console.log(`[ OK ] updater error codes aligned (${rustCodes.size})`);
