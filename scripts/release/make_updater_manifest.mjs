/**
 * 生成 Tauri 更新清单（schema_version 2）。
 *
 * 保留插件必需字段，附加发布身份、灰度与兼容区间，供客户端做完整性校验。
 * 安装包哈希、字节数与文件版本由本脚本计算或从 PE 资源读取，不接受手工填写。
 * 版本必须来自根 VERSION 的同步结果，禁止在此推导。
 */
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { basename, dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..", "..");
const CORE_API_HEADER = resolve(REPO_ROOT, "core", "include", "verthys.h");
const CORE_CONTAINER_HEADER = resolve(
  REPO_ROOT,
  "core",
  "src",
  "container",
  "shared",
  "verthys_container_v3.h",
);
const DEFAULT_OUT = resolve(REPO_ROOT, "build", "updater", "latest.json");
const DEFAULT_TARGET = "windows-x86_64";
const VERSION_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const RELEASE_ID_RE = /^[0-9a-hjkmnp-tv-z]{13}$/;
const LEGACY_RELEASE_ID_RE = /^\d{8}-\d{6}-(\d+\.\d+\.\d+)-[0-9a-f]{8}$/;
const CHANNELS = new Set(["local", "internal", "beta", "stable"]);
const NOTES_SECTION_TYPES = new Set(["security", "changed", "fixed", "added"]);

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

function parseIntegerArg(value, name, min, max) {
  const parsed = Number(value);
  if (!value.trim() || !Number.isInteger(parsed) || parsed < min || parsed > max) {
    fail(`${name} 必须是 ${min} 到 ${max} 之间的整数，当前为: ${value}`);
  }
  return parsed;
}

function parseBooleanArg(value, name) {
  if (value === "true") return true;
  if (value === "false") return false;
  fail(`${name} 只能是 true 或 false，当前为: ${value}`);
}

/**
 * 解析核心头文件中的整型宏。
 *
 * 兼容区间必须与真实核心版本一致；手写默认值会在核心升级后静默失配，
 * 因此生成器直接读取头文件，缺失或格式非法时拒绝生成清单。
 */
export function parseDefineU32(source, symbol) {
  for (const line of source.split(/\r?\n/)) {
    const parts = line.trim().split(/\s+/);
    if (parts[0] !== "#define" || parts[1] !== symbol || parts.length < 3) continue;
    const raw = parts[2].replace(/[uUlL]+$/, "");
    let value = Number.NaN;
    if (/^0x[0-9a-f]+$/i.test(raw)) value = Number.parseInt(raw.slice(2), 16);
    else if (/^\d+$/.test(raw)) value = Number.parseInt(raw, 10);
    if (Number.isInteger(value)) return value;
  }
  return null;
}

/** 读取当前核心的 ABI 与容器格式版本。 */
export function readCoreVersions() {
  return {
    api: parseDefineU32(readFileSync(CORE_API_HEADER, "utf8"), "VERTHYS_API_VERSION"),
    container: parseDefineU32(readFileSync(CORE_CONTAINER_HEADER, "utf8"), "VERTHYS_V3_VERSION"),
  };
}

/** 将 ABI 数值格式化为清单使用的四位十六进制文本。 */
export function formatAbiVersion(value) {
  return `0x${value.toString(16).toUpperCase().padStart(4, "0")}`;
}

/**
 * 校验兼容区间是否覆盖当前核心。
 *
 * 清单声明的区间不包含当前核心时，本机客户端会拒绝自己的发布；桥接发布
 * 允许下限低于当前值，但上限必须覆盖当前值。返回 null 表示通过。
 */
export function compatibilityRangeError(abiMin, abiMax, containerMin, containerMax, core) {
  const min = Number.parseInt(abiMin.slice(2), 16);
  const max = Number.parseInt(abiMax.slice(2), 16);
  if (!Number.isInteger(min) || !Number.isInteger(max)) {
    return "兼容 ABI 区间不是合法十六进制";
  }
  if (min > core.api || max < core.api) {
    return "兼容 ABI 区间不包含当前核心 ABI";
  }
  if (containerMin > core.container || containerMax < core.container) {
    return "容器兼容区间不包含当前容器版本";
  }
  return null;
}

/**
 * 把 PE 文件版本或用户输入归一化为 MAJOR.MINOR.PATCH。
 * 多段版本只取前三段，避免把修订号写进清单后破坏严格比较。
 */
export function normalizeFileVersion(raw) {
  if (typeof raw !== "string") return null;
  const match = raw.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!match) return null;
  return `${Number(match[1])}.${Number(match[2])}.${Number(match[3])}`;
}

const CROCKFORD_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";

/**
 * 把安装包 SHA256 压缩为 13 位 Crockford Base32 融合编码。
 *
 * 取摘要前 8 字节（64 bit）编码为 13 个字符；字母表排除 i/l/o/u，避免人工
 * 抄写混淆。该编码只由安装包最终字节决定，版本与构建信息已隐式绑定在字节中。
 */
export function buildReleaseId(sha256Hex) {
  if (!SHA256_RE.test(sha256Hex)) {
    throw new Error("安装包 SHA256 必须是 64 位小写十六进制");
  }
  let bits = "";
  for (let index = 0; index < 8; index++) {
    bits += Number.parseInt(sha256Hex.slice(index * 2, index * 2 + 2), 16)
      .toString(2)
      .padStart(8, "0");
  }
  bits = bits.padEnd(65, "0");
  let output = "";
  for (let index = 0; index < 13; index++) {
    output += CROCKFORD_ALPHABET[Number.parseInt(bits.slice(index * 5, index * 5 + 5), 2)];
  }
  return output;
}

/** 判断发布标识是否合法；新格式为融合哈希，旧日期格式仅用于兼容存量。 */
export function isReleaseId(value) {
  return RELEASE_ID_RE.test(value) || LEGACY_RELEASE_ID_RE.test(value);
}

/**
 * 构造 release 级不可变物料地址。
 *
 * 服务端按 /releases/<release_id>/artifacts/<文件名> 存放安装包；路径含发布标识，
 * 因此可以长缓存且永不覆盖。根地址必须与清单端点同源，避免放宽客户端主机白名单。
 */
export function buildArtifactUrl(artifactRoot, releaseId, fileName) {
  const base = artifactRoot.trim().replace(/\/+$/, "");
  const parsed = new URL(base);
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("物料根地址协议必须是 http 或 https");
  }
  return new URL(`${base}/${releaseId}/artifacts/${encodeURIComponent(fileName)}`).toString();
}

/**
 * 读取安装包 PE 资源中的文件版本；非 Windows 或读取失败时返回空，由调用方回退。
 * 路径通过环境变量传入，避免命令行拼接导致路径被二次解释。
 */
function readPeFileVersion(installerPath) {
  if (process.platform !== "win32") return null;
  const command = "(Get-Item -LiteralPath $env:VERTHYS_INSTALLER).VersionInfo.FileVersion";
  for (const shell of ["powershell.exe", "pwsh.exe"]) {
    const result = spawnSync(shell, ["-NoProfile", "-NonInteractive", "-Command", command], {
      encoding: "utf8",
      timeout: 15000,
      windowsHide: true,
      env: { ...process.env, VERTHYS_INSTALLER: installerPath },
    });
    if (!result.error && result.status === 0 && result.stdout && result.stdout.trim()) {
      return result.stdout.trim();
    }
  }
  return null;
}

/**
 * 更新说明分区既可传内联 JSON，也可传 JSON 文件路径；无法读取文件时按内联内容解析。
 */
function loadNotesSections(value) {
  let raw = value.trim();
  if (!raw) fail("--notes-sections 取值不能为空");
  let source = "命令行参数";
  const candidate = resolve(raw);
  if (existsSync(candidate)) {
    raw = readFileSync(candidate, "utf8");
    source = `文件 ${candidate}`;
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    fail(`--notes-sections 解析失败（${source}）: ${error.message}`);
  }
  if (!Array.isArray(parsed)) fail("notes_sections 必须是数组");

  return parsed.map((section, index) => {
    if (!section || typeof section !== "object" || Array.isArray(section)) {
      fail(`notes_sections[${index}] 必须是对象`);
    }
    if (typeof section.type !== "string" || !NOTES_SECTION_TYPES.has(section.type)) {
      fail(`notes_sections[${index}].type 必须是 security/changed/fixed/added 之一`);
    }
    if (!Array.isArray(section.items) || section.items.length === 0) {
      fail(`notes_sections[${index}].items 必须是非空数组`);
    }
    if (!section.items.every((item) => typeof item === "string" && item.trim())) {
      fail(`notes_sections[${index}].items 必须全部是非空字符串`);
    }
    return { type: section.type, items: section.items.map((item) => item.trim()) };
  });
}

function parseRevokedReleaseIds(value) {
  if (value === undefined) return [];
  const raw = value.trim();
  if (!raw) return [];
  let ids;
  if (raw.startsWith("[")) {
    try {
      ids = JSON.parse(raw);
    } catch (error) {
      fail(`--revoked-release-ids 解析失败: ${error.message}`);
    }
  } else {
    ids = raw.split(",").map((item) => item.trim()).filter(Boolean);
  }
  if (!Array.isArray(ids) || !ids.every((id) => typeof id === "string" && isReleaseId(id))) {
    fail("--revoked-release-ids 中的每一项都必须是合法的 release_id");
  }
  return ids;
}

function printHelp() {
  console.log(
    [
      "用法:",
      "  node scripts/release/make_updater_manifest.mjs \\",
      "    --version 4.1.3 \\",
      "    --installer <安装包路径> \\",
      "    --signature <签名文件路径> \\",
      "    --url <安装包下载地址> \\",
      "    [--artifact-root <物料根地址，按 /releases/<release_id>/artifacts 派生>] \\",
      "    [--out <清单输出路径>] [--target windows-x86_64] [--channel local] \\",
      "    [--release-id <13 位融合哈希或旧日期格式>] [--notes <更新说明>] \\",
      "    [--notes-sections <JSON 数组或 JSON 文件路径>] \\",
      "    [--min-version <版本>] [--force-below <版本>] \\",
      "    [--rollout-percentage 0-100] [--rollout-salt <盐>] [--paused true|false] \\",
      "    [--revoked-release-ids <JSON 数组或逗号分隔>] \\",
      "    [--compat-abi-min <hex>] [--compat-abi-max <hex>] \\",
      "    [--compat-container-min <n>] [--compat-container-max <n>] \\",
      "    [--file-version <版本>] [--authenticode-subject <主题>] \\",
      "    [--authenticode-sha256 <64 位十六进制>] [--manifest-signature <base64>] \\",
      "    [--manifest-key-id <key id>]",
    ].join("\n"),
  );
}

function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.help) {
    printHelp();
    return;
  }

  const version = (args.version ?? "").trim();
  const installerPath = args.installer ? resolve(args.installer) : "";
  const signaturePath = args.signature ? resolve(args.signature) : "";
  const downloadUrl = (args.url ?? "").trim();
  const artifactRoot = (args["artifact-root"] ?? "").trim();
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
  if (!/^(windows|darwin|linux)-[a-z0-9_]+$/.test(target)) {
    fail(`目标标识格式不合法: ${target}`);
  }

  let parsedUrl = null;
  if (downloadUrl) {
    try {
      parsedUrl = new URL(downloadUrl);
    } catch {
      fail(`下载地址不是合法 URL: ${downloadUrl || "<空>"}`);
    }
    if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") {
      fail(`下载地址协议必须是 http 或 https，当前为: ${parsedUrl.protocol}`);
    }
  }
  if (artifactRoot) {
    let artifactRootUrl = null;
    try {
      artifactRootUrl = new URL(artifactRoot);
    } catch {
      fail(`物料根地址不是合法 URL: ${artifactRoot || "<空>"}`);
    }
    if (artifactRootUrl.protocol !== "http:" && artifactRootUrl.protocol !== "https:") {
      fail(`物料根地址协议必须是 http 或 https，当前为: ${artifactRootUrl.protocol}`);
    }
  }
  if (!parsedUrl && !artifactRoot) {
    fail("必须提供 --url 或 --artifact-root");
  }

  const signatureText = readFileSync(signaturePath, "utf8").trim();
  if (!signatureText) fail("签名文件内容为空");

  const signatureDecoded = Buffer.from(signatureText, "base64").toString("utf8");
  if (!/^untrusted comment:/.test(signatureDecoded) || !/\ntrusted comment:/.test(signatureDecoded)) {
    fail("签名内容缺少 minisign 头部，拒绝写入清单");
  }

  const installerBytes = readFileSync(installerPath);
  if (installerBytes.length === 0) fail("安装包为空文件");
  const installerSha256 = createHash("sha256").update(installerBytes).digest("hex");

  const channel = (args.channel ?? "local").trim();
  if (!CHANNELS.has(channel)) {
    fail(`渠道必须是 local/internal/beta/stable 之一，当前为: ${channel || "<空>"}`);
  }

  let releaseId;
  if (args["release-id"] !== undefined) {
    releaseId = args["release-id"].trim();
    if (!isReleaseId(releaseId)) {
      fail(`release_id 必须是 13 位融合哈希或旧的日期格式，当前为: ${releaseId || "<空>"}`);
    }
    const legacy = releaseId.match(LEGACY_RELEASE_ID_RE);
    if (legacy) {
      if (legacy[1] !== version) {
        fail(`release_id 中的版本必须与 --version 一致，当前为: ${legacy[1]} 与 ${version}`);
      }
    } else if (releaseId !== buildReleaseId(installerSha256)) {
      fail("融合哈希 release_id 必须由安装包 SHA256 派生");
    }
  } else {
    releaseId = buildReleaseId(installerSha256);
  }

  let installerDownloadUrl = parsedUrl ? parsedUrl.toString() : "";
  if (artifactRoot) {
    try {
      installerDownloadUrl = buildArtifactUrl(artifactRoot, releaseId, basename(installerPath));
    } catch (error) {
      fail(error.message);
    }
  }

  const minVersion = args["min-version"]?.trim();
  if (minVersion !== undefined && !VERSION_RE.test(minVersion)) {
    fail(`--min-version 必须是 MAJOR.MINOR.PATCH 形式的纯数字，当前为: ${minVersion || "<空>"}`);
  }
  const forceBelow = args["force-below"]?.trim();
  if (forceBelow !== undefined && !VERSION_RE.test(forceBelow)) {
    fail(`--force-below 必须是 MAJOR.MINOR.PATCH 形式的纯数字，当前为: ${forceBelow || "<空>"}`);
  }

  const notesSections = args["notes-sections"] === undefined ? null : loadNotesSections(args["notes-sections"]);

  const rolloutPercentage =
    args["rollout-percentage"] === undefined
      ? 100
      : parseIntegerArg(args["rollout-percentage"], "--rollout-percentage", 0, 100);
  const rolloutSalt = args["rollout-salt"] === undefined ? "local" : args["rollout-salt"].trim();
  if (!rolloutSalt) fail("--rollout-salt 不能为空");

  const paused = args.paused === undefined ? false : parseBooleanArg(args.paused, "--paused");
  const revokedReleaseIds = parseRevokedReleaseIds(args["revoked-release-ids"]);

  const coreVersions = readCoreVersions();
  if (coreVersions.api === null || coreVersions.container === null) {
    fail("无法从核心头文件读取 ABI 或容器版本，拒绝生成清单");
  }
  const abiMin = (args["compat-abi-min"] ?? formatAbiVersion(coreVersions.api)).trim();
  const abiMax = (args["compat-abi-max"] ?? formatAbiVersion(coreVersions.api)).trim();
  if (!/^0x[0-9a-fA-F]+$/.test(abiMin) || !/^0x[0-9a-fA-F]+$/.test(abiMax)) {
    fail(`兼容 ABI 必须使用 0x 前缀的十六进制，当前为: ${abiMin} / ${abiMax}`);
  }
  const containerMin =
    args["compat-container-min"] === undefined
      ? coreVersions.container
      : parseIntegerArg(args["compat-container-min"], "--compat-container-min", 0, Number.MAX_SAFE_INTEGER);
  const containerMax =
    args["compat-container-max"] === undefined
      ? coreVersions.container
      : parseIntegerArg(args["compat-container-max"], "--compat-container-max", 0, Number.MAX_SAFE_INTEGER);
  if (containerMin > containerMax) {
    fail(`容器兼容区间不合法: ${containerMin} > ${containerMax}`);
  }
  const rangeError = compatibilityRangeError(
    abiMin,
    abiMax,
    containerMin,
    containerMax,
    coreVersions,
  );
  if (rangeError) fail(rangeError);
  if (
    abiMin !== formatAbiVersion(coreVersions.api) ||
    abiMax !== formatAbiVersion(coreVersions.api)
  ) {
    console.log(
      `[WARN] 兼容 ABI 区间 ${abiMin} ~ ${abiMax} 包含当前核心 ${formatAbiVersion(coreVersions.api)}；低于当前值的下限仅用于桥接发布`,
    );
  }

  let fileVersion = normalizeFileVersion(readPeFileVersion(installerPath));
  if (!fileVersion && args["file-version"] !== undefined) {
    fileVersion = normalizeFileVersion(args["file-version"]);
    if (!fileVersion) {
      fail(`--file-version 无法归一化为 MAJOR.MINOR.PATCH，当前为: ${args["file-version"]}`);
    }
  }
  if (!fileVersion) fileVersion = version;

  const authenticodeSubject = args["authenticode-subject"]?.trim();
  const authenticodeSha256 = args["authenticode-sha256"]?.trim().toLowerCase();
  if (authenticodeSha256 !== undefined && !SHA256_RE.test(authenticodeSha256)) {
    fail(`--authenticode-sha256 必须是 64 位小写十六进制，当前为: ${authenticodeSha256 || "<空>"}`);
  }
  if (authenticodeSubject === "") fail("--authenticode-subject 不能为空");
  const platform = {
    url: installerDownloadUrl,
    signature: signatureText,
    sha256: installerSha256,
    size: installerBytes.length,
    file_version: fileVersion,
  };
  if (authenticodeSubject !== undefined || authenticodeSha256 !== undefined) {
    platform.authenticode = {
      required: true,
      subject: authenticodeSubject ?? "",
      sha256: authenticodeSha256 ?? "",
    };
  }

  let manifestSignature;
  if (args["manifest-signature"] !== undefined) {
    const raw = args["manifest-signature"].trim();
    if (!raw || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw) || raw.length % 4 !== 0) {
      fail("--manifest-signature 必须是合法的 base64 字符串");
    }
    if (Buffer.from(raw, "base64").length === 0) fail("--manifest-signature 解码后为空");
    manifestSignature = {
      alg: "minisign",
      key_id: (args["manifest-key-id"] ?? "").trim(),
      signature: raw,
    };
  }

  const platforms = { [target]: platform };
  if (target.startsWith("windows-")) {
    platforms[`${target}-nsis`] = platform;
  }

  const manifest = {
    schema_version: 2,
    release_id: releaseId,
    version,
    channel,
    pub_date: new Date().toISOString(),
    notes,
  };
  if (notesSections) manifest.notes_sections = notesSections;
  if (minVersion !== undefined) manifest.min_version = minVersion;
  if (forceBelow !== undefined) manifest.force_below = forceBelow;
  manifest.rollout = { percentage: rolloutPercentage, salt: rolloutSalt };
  manifest.paused = paused;
  manifest.revoked_release_ids = revokedReleaseIds;
  manifest.compatibility = {
    abi: { min: abiMin, max: abiMax },
    container: { min: containerMin, max: containerMax },
  };
  manifest.platforms = platforms;
  if (manifestSignature !== undefined) manifest.manifest_signature = manifestSignature;

  mkdirSync(dirname(outPath), { recursive: true });
  const tempPath = `${outPath}.tmp`;
  writeFileSync(tempPath, `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
  renameSync(tempPath, outPath);

  console.log(`[ OK ] 清单已写入: ${outPath}`);
  console.log(`[ OK ] 版本: ${version} / 文件版本: ${fileVersion}`);
  console.log(`[ OK ] release_id: ${releaseId}`);
  console.log(`[ OK ] 渠道: ${channel}`);
  console.log(`[ OK ] 目标: ${Object.keys(platforms).join(", ")}`);
  console.log(`[ OK ] SHA256: ${platform.sha256}`);
  console.log(`[ OK ] 安装包大小: ${platform.size} 字节`);
}

const invokedDirectly =
  process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href;
if (invokedDirectly) main();
