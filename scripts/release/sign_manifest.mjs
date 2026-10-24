/*
 * 为更新清单附加签名。
 *
 * 清单签名覆盖去掉 manifest_signature 后的规范化 JSON；键排序、无空白，
 * 与客户端验签使用同一规范化规则。私钥只从环境变量或受控用户目录读取，
 * 不写入清单、临时文件与输出目录之外的任何位置。
 */
import { createHash } from "node:crypto";
import { existsSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..", "..");
const TAURI_DIR = join(REPO_ROOT, "verthys-tauri");

function fail(message) {
  console.error(`[FAIL] ${message}`);
  process.exit(1);
}

function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isInteger(value)) fail("清单不允许浮点数");
    return String(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  fail(`无法规范化的 JSON 类型: ${typeof value}`);
}

function readKeyMaterial() {
  const envKey = process.env.TAURI_SIGNING_PRIVATE_KEY?.trim();
  const envPassword = process.env.TAURI_SIGNING_PRIVATE_KEY_PASSWORD?.trim();
  if (envKey) return { key: envKey, password: envPassword ?? "" };

  const keyPath = join(homedir(), ".tauri", "verthys-updater.key");
  const passPath = join(homedir(), ".tauri", "verthys-updater.pass");
  if (!existsSync(keyPath)) fail("未找到签名私钥，请注入环境变量或准备受控密钥文件");
  const key = readFileSync(keyPath, "utf8").trim();
  const password = existsSync(passPath) ? readFileSync(passPath, "utf8").trim() : "";
  return { key, password };
}

function keyIdFromPublicKey() {
  const configPath = join(TAURI_DIR, "src-tauri", "tauri.conf.json");
  const config = JSON.parse(readFileSync(configPath, "utf8"));
  const encoded = config?.plugins?.updater?.pubkey;
  if (typeof encoded !== "string" || !encoded) fail("配置中缺少更新公钥");
  const text = Buffer.from(encoded, "base64").toString("utf8");
  const match = text.match(/minisign public key:\s*([0-9A-Fa-f]+)/);
  return match ? match[1].toUpperCase() : "";
}

function main() {
  const manifestPath = process.argv[2];
  if (!manifestPath) fail("用法: node scripts/release/sign_manifest.mjs <latest.json>");
  const absolute = resolve(manifestPath);
  if (!existsSync(absolute)) fail(`清单不存在: ${absolute}`);

  const manifest = JSON.parse(readFileSync(absolute, "utf8"));
  if (!manifest || typeof manifest !== "object" || Array.isArray(manifest)) {
    fail("清单根节点必须是对象");
  }
  delete manifest.manifest_signature;
  const canonical = canonicalJson(manifest);

  // 先完成全部前置检查（公钥、私钥、CLI）再落临时文件：
  // 任何前置失败都不得在输出目录留下半成品。
  const keyId = keyIdFromPublicKey();
  const { key, password } = readKeyMaterial();
  const tauriCli = join(TAURI_DIR, "node_modules", "@tauri-apps", "cli", "tauri.js");
  if (!existsSync(tauriCli)) {
    fail(`Tauri CLI 不存在: ${tauriCli}（请在 verthys-tauri 执行 npm ci）`);
  }

  const canonicalPath = `${absolute}.canonical.json`;
  writeFileSync(canonicalPath, canonical, "utf8");
  const childEnv = {
    ...process.env,
    TAURI_SIGNING_PRIVATE_KEY: key,
    TAURI_SIGNING_PRIVATE_KEY_PASSWORD: password,
  };
  const signaturePath = `${canonicalPath}.sig`;
  const command = spawnSync(
    process.execPath,
    [tauriCli, "signer", "sign", canonicalPath],
    {
      cwd: TAURI_DIR,
      encoding: "utf8",
      timeout: 60000,
      windowsHide: true,
      env: childEnv,
    },
  );
  if (command.error || command.status !== 0) {
    rmSync(canonicalPath, { force: true });
    rmSync(signaturePath, { force: true });
    fail(`清单签名失败: ${command.error?.message ?? command.stderr ?? "未知错误"}`);
  }

  if (!existsSync(signaturePath)) {
    rmSync(canonicalPath, { force: true });
    fail("签名工具未生成 .sig 文件");
  }
  const signatureText = readFileSync(signaturePath, "utf8").trim();
  const signature = signatureText;
  const digest = createHash("sha256").update(canonical, "utf8").digest("hex");

  manifest.manifest_signature = {
    alg: "minisign",
    key_id: keyId,
    signature,
  };
  const tempPath = `${absolute}.tmp`;
  writeFileSync(tempPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  renameSync(tempPath, absolute);
  rmSync(canonicalPath, { force: true });
  rmSync(signaturePath, { force: true });

  console.log(`[ OK ] 清单已签名: ${absolute}`);
  console.log(`[ OK ] 规范化 SHA256: ${digest}`);
}

main();
