/**
 * 生成 Tauri 更新清单 latest.json。
 *
 * 输入安装包与签名文件，输出静态清单；签名内容按原文本写入，不做二次编码。
 * 清单同时写入带安装器后缀与基础目标键，兼容运行时的目标查找顺序。
 * 版本必须来自根 VERSION 的同步结果，禁止在此推导。
 */
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");
const DEFAULT_OUT = resolve(REPO_ROOT, "build", "updater", "latest.json");
const DEFAULT_TARGET = "windows-x86_64";
const VERSION_RE = /^\d+\.\d+\.\d+$/;

function fail(message) {
  console.error(`[FAIL] ${message}`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i];
    if (raw === "--help" || raw === "-h") {
      args.help = "1";
      continue;
    }
    if (!raw.startsWith("--")) fail(`无法识别的参数: ${raw}`);
    const key = raw.slice(2);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) fail(`参数缺少取值: ${raw}`);
    args[key] = value;
    i++;
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));

if (args.help) {
  console.log(
    [
      "用法:",
      "  node scripts/make_updater_manifest.mjs \\",
      "    --version 4.1.3 \\",
      "    --installer <安装包路径> \\",
      "    --signature <签名文件路径> \\",
      "    --url <安装包下载地址> \\",
      "    [--out <清单输出路径>] [--notes <更新说明>] [--target windows-x86_64]",
    ].join("\n"),
  );
  process.exit(0);
}

const version = (args.version ?? "").trim();
const installerPath = args.installer ? resolve(args.installer) : "";
const signaturePath = args.signature ? resolve(args.signature) : "";
const downloadUrl = (args.url ?? "").trim();
const outPath = args.out ? resolve(args.out) : DEFAULT_OUT;
const target = (args.target ?? DEFAULT_TARGET).trim();
const notes = args.notes ?? "";

if (!VERSION_RE.test(version)) {
  fail(`版本号必须是 MAJOR.MINOR.PATCH 形式的纯数字，当前为: ${version || "<空>"}`);
}
if (!installerPath || !existsSync(installerPath)) {
  fail(`安装包不存在: ${installerPath || "<空>"}`);
}
if (!signaturePath || !existsSync(signaturePath)) {
  fail(`签名文件不存在: ${signaturePath || "<空>"}`);
}
if (statSync(installerPath).size <= 0) {
  fail("安装包为空文件");
}
if (!/^(windows|darwin|linux)-[a-z0-9_]+$/.test(target)) {
  fail(`目标标识格式不合法: ${target}`);
}

let parsedUrl;
try {
  parsedUrl = new URL(downloadUrl);
} catch {
  fail(`下载地址不是合法 URL: ${downloadUrl || "<空>"}`);
}
if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
  fail(`下载地址协议必须是 http 或 https，当前为: ${parsedUrl.protocol}`);
}

const signatureText = readFileSync(signaturePath, "utf8").trim();
if (!signatureText) fail("签名文件内容为空");

const signatureDecoded = Buffer.from(signatureText, "base64").toString("utf8");
if (!/^untrusted comment:/.test(signatureDecoded) || !/\ntrusted comment:/.test(signatureDecoded)) {
  fail("签名内容缺少 minisign 头部，拒绝写入清单");
}

const platform = { signature: signatureText, url: parsedUrl.toString() };
const platforms = { [target]: platform };
if (target.startsWith("windows-")) {
  platforms[`${target}-nsis`] = platform;
}

const manifest = {
  version,
  notes,
  pub_date: new Date().toISOString(),
  platforms,
};

mkdirSync(dirname(outPath), { recursive: true });
const tempPath = `${outPath}.tmp`;
writeFileSync(tempPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
renameSync(tempPath, outPath);

console.log(`[ OK ] 清单已写入: ${outPath}`);
console.log(`[ OK ] 版本: ${version}`);
console.log(`[ OK ] 目标: ${Object.keys(platforms).join(", ")}`);
console.log(`[ OK ] 安装包大小: ${statSync(installerPath).size} 字节`);
