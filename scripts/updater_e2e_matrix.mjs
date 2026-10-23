/*
 * 本机更新端到端矩阵。
 *
 * 用真实已安装客户端、真实回环服务与真实签名物料执行负向与正向用例。
 * 每个用例只替换清单，不替换安装包；因此失败必须发生在下载或安装之前，
 * 或由准备阶段的哈希 / 大小 / PE 校验拦截。脚本结束会恢复原始清单。
 *
 * 使用前提：
 *   1. 已安装的客户端带 e2e_update 钩子，且版本低于待发布版本；
 *   2. 回环服务已在 127.0.0.1:8765 运行，服务目录为 --root；
 *   3. 清单签名私钥位于受控用户目录或已注入环境变量。
 *
 * 退出码：任一用例未命中预期即返回 1，并保留逐项结果供排查。
 */
import { spawn, spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");
const DEFAULT_LOG_DIR = join(process.env.APPDATA ?? homedir(), "com.verthys.app", "logs", "updater");
const LEGACY_LOG_DIR = join(process.env.APPDATA ?? homedir(), "com.verthys.app", "updater", "logs");
const EXPECT_TIMEOUT_MS = 30000;
const POSITIVE_TIMEOUT_MS = 180000;

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
    if (raw === "--include-positive") {
      args["include-positive"] = "1";
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

function platformEntries(manifest) {
  const platforms = manifest.platforms;
  if (!platforms || typeof platforms !== "object") fail("清单缺少 platforms");
  return Object.values(platforms).filter((item) => item && typeof item === "object");
}

function mutatePlatforms(manifest, mutate) {
  for (const platform of platformEntries(manifest)) mutate(platform);
}

function stopClient() {
  const script = [
    "Get-Process -Name 'Verthys','verthys-worker' -ErrorAction SilentlyContinue |",
    "Stop-Process -Force -ErrorAction SilentlyContinue",
  ].join(" ");
  spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    windowsHide: true,
    timeout: 15000,
  });
}

function logFiles() {
  const files = [];
  for (const dir of [DEFAULT_LOG_DIR, LEGACY_LOG_DIR]) {
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir)) {
      if (name.startsWith("updater-") && name.endsWith(".jsonl")) {
        files.push(join(dir, name));
      }
    }
  }
  return files;
}

function snapshotLogs() {
  const snapshot = new Map();
  for (const path of logFiles()) {
    snapshot.set(path, statSync(path).size);
  }
  return snapshot;
}

function readNewRecords(snapshot) {
  const records = [];
  for (const path of logFiles()) {
    const offset = snapshot.get(path) ?? 0;
    const size = statSync(path).size;
    if (size <= offset) continue;
    let text;
    try {
      const payload = readFileSync(path);
      text = payload.subarray(offset, size).toString("utf8");
    } catch {
      continue;
    }
    snapshot.set(path, size);
    for (const line of text.split(/\r?\n/)) {
      if (!line.trim()) continue;
      try {
        records.push(JSON.parse(line));
      } catch {
        // 日志写入过程中可能截断最后一行，下一轮从新偏移继续读取。
      }
    }
  }
  return records;
}

function matches(record, expected) {
  if (record.event !== expected.event) return false;
  if (expected.code && record.code !== expected.code) return false;
  return true;
}

/**
 * 签名变体清单。
 *
 * 签名覆盖去掉 manifest_signature 后的规范化 JSON；任何字段修改都必须重签，
 * 只有“清单签名篡改”用例故意跳过重签。
 */
function writeVariant(name, manifest, tamper) {
  const dir = join(REPO_ROOT, "build", "e2e-variants");
  mkdirSync(dir, { recursive: true });
  const path = join(dir, `${name}.json`);
  const payload = structuredClone(manifest);
  if (!tamper) delete payload.manifest_signature;
  writeFileSync(path, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  if (!tamper) {
    const signer = join(SCRIPT_DIR, "sign_manifest.mjs");
    const result = spawnSync(process.execPath, [signer, path], {
      encoding: "utf8",
      timeout: 60000,
      windowsHide: true,
    });
    if (result.status !== 0) {
      fail(`变体签名失败 ${name}: ${result.stderr || result.stdout}`);
    }
  }
  return path;
}

function waitForOutcome(snapshot, expected, timeoutMs, startedAt) {
  return new Promise((resolvePromise) => {
    const all = [];
    const timer = setInterval(() => {
      const records = readNewRecords(snapshot);
      all.push(...records);
      for (const record of records) {
        if (matches(record, expected)) {
          clearInterval(timer);
          resolvePromise({ ok: true, record, records: all });
          return;
        }
      }
      if (Date.now() - startedAt > timeoutMs) {
        clearInterval(timer);
        resolvePromise({ ok: false, records: all });
      }
    }, 250);
  });
}

async function runCase(testCase, state) {
  stopClient();
  const snapshot = snapshotLogs();
  const startedAt = Date.now();
  const child = spawn(state.app, [], {
    cwd: dirname(state.app),
    env: { ...process.env, VERTHYS_E2E_UPDATE: "1" },
    stdio: "ignore",
    windowsHide: false,
  });
  child.on("error", (error) => {
    console.error(`[WARN] 客户端启动失败 ${testCase.name}: ${error.message}`);
  });

  const timeout = testCase.positive ? POSITIVE_TIMEOUT_MS : EXPECT_TIMEOUT_MS;
  const outcome = await waitForOutcome(snapshot, testCase.expect, timeout, startedAt);
  // 健康结论落盘后才归档标记；留出完成窗口，避免过早终止新进程。
  if (testCase.positive && outcome.ok) {
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 2000));
  }
  stopClient();
  return { ...outcome, elapsedMs: Date.now() - startedAt };
}

function installedVersion(app) {
  const script = `(Get-Item -LiteralPath $env:VERTHYS_E2E_APP).VersionInfo.FileVersion`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    encoding: "utf8",
    timeout: 15000,
    windowsHide: true,
    env: { ...process.env, VERTHYS_E2E_APP: app },
  });
  return result.status === 0 ? result.stdout.trim() : "";
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(
      [
        "用法:",
        "  node scripts/updater_e2e_matrix.mjs --app <Verthys.exe> --root <服务目录> --base <有效清单>",
        "    [--cases <名称,名称>] [--include-positive]",
        "",
        "服务需已在本机回环地址运行；脚本只替换 latest.json。",
      ].join("\n"),
    );
    return;
  }

  const app = resolve(args.app ?? "");
  const root = resolve(args.root ?? join(REPO_ROOT, "build", "updater"));
  const basePath = resolve(args.base ?? join(root, "latest.json"));
  if (!existsSync(app)) fail(`客户端不存在: ${app}`);
  if (!existsSync(basePath)) fail(`基准清单不存在: ${basePath}`);

  const base = JSON.parse(readFileSync(basePath, "utf8"));
  const version = String(base.version ?? "");
  if (!version) fail("基准清单缺少 version");
  const newInstaller = join(root, basename(new URL(platformEntries(base)[0].url).pathname));
  if (!existsSync(newInstaller)) fail(`新安装包不存在: ${newInstaller}`);
  const newSignature = `${newInstaller}.sig`;
  if (!existsSync(newSignature)) fail(`新安装包签名不存在: ${newSignature}`);

  const variantPaths = {};
  const register = (name, mutate, tamper = false) => {
    const manifest = structuredClone(base);
    mutate(manifest);
    variantPaths[name] = writeVariant(name, manifest, tamper);
  };

  register("manifest-sig-tampered", (manifest) => {
    manifest.notes = `${manifest.notes ?? ""} tampered`;
  }, true);

  register("channel-mismatch", (manifest) => {
    manifest.channel = "stable";
  });

  register("paused", (manifest) => {
    manifest.paused = true;
  });

  register("rollout-excluded", (manifest) => {
    manifest.rollout = { percentage: 0, salt: "e2e-matrix" };
  });

  register("bridge-required", (manifest) => {
    manifest.min_version = "9.9.9";
  });

  register("compat-blocked", (manifest) => {
    manifest.compatibility = {
      ...(manifest.compatibility ?? {}),
      abi: { min: "0x7FFF", max: "0x7FFF" },
    };
  });

  register("revoked", (manifest) => {
    manifest.revoked_release_ids = [manifest.release_id];
  });

  register("hash-mismatch", (manifest) => {
    mutatePlatforms(manifest, (platform) => {
      platform.sha256 = "0".repeat(64);
    });
  });

  register("size-mismatch", (manifest) => {
    mutatePlatforms(manifest, (platform) => {
      platform.size = Number(platform.size) + 1;
    });
  });

  // 复用同一安装包，只把清单版本抬到 4.1.6；验签、哈希与大小都真实，
  // 唯一不一致的是 PE 文件版本，从而精确命中准备阶段的版本身份校验。
  register("pe-version-mismatch", (manifest) => {
    manifest.version = "4.1.6";
    mutatePlatforms(manifest, (platform) => {
      platform.file_version = "4.1.6";
    });
  });

  const cases = [
    {
      name: "manifest-sig-tampered",
      expect: { event: "manifest_sig_invalid", code: "E_UPDATER_MANIFEST_SIG_INVALID" },
    },
    {
      name: "channel-mismatch",
      expect: { event: "manifest_invalid", code: "E_UPDATER_CHANNEL_MISMATCH" },
    },
    { name: "paused", expect: { event: "check_miss" } },
    { name: "rollout-excluded", expect: { event: "check_miss" } },
    {
      name: "bridge-required",
      expect: { event: "manifest_invalid", code: "E_UPDATER_BRIDGE_REQUIRED" },
    },
    {
      name: "compat-blocked",
      expect: { event: "manifest_invalid", code: "E_UPDATER_COMPAT_BLOCKED" },
    },
    {
      name: "revoked",
      expect: { event: "manifest_invalid", code: "E_UPDATER_INSTALL_REVOKED" },
    },
    { name: "hash-mismatch", expect: { event: "hash_mismatch", code: "E_UPDATER_HASH_MISMATCH" } },
    { name: "size-mismatch", expect: { event: "size_mismatch", code: "E_UPDATER_SIZE_MISMATCH" } },
  ];
  cases.push({
    name: "pe-version-mismatch",
    expect: { event: "pe_version_mismatch", code: "E_UPDATER_PE_VERSION_MISMATCH" },
  });
  if (args["include-positive"]) {
    cases.push({
      name: "positive",
      positive: true,
      expect: { event: "health_ok" },
    });
  }

  // 指定子集时仍保留声明顺序，便于复跑单条失败用例而不改变执行语义。
  const selected = args.cases
    ? new Set(args.cases.split(",").map((item) => item.trim()).filter(Boolean))
    : null;
  const runnable = selected ? cases.filter((item) => selected.has(item.name)) : cases;
  if (selected && runnable.length !== selected.size) {
    fail(`未知用例: ${[...selected].filter((name) => !cases.some((item) => item.name === name)).join(", ")}`);
  }

  const originalManifest = readFileSync(join(root, "latest.json"));
  const results = [];
  try {
    for (const testCase of runnable) {
      if (testCase.positive) {
        copyFileSync(basePath, join(root, "latest.json"));
      } else {
        copyFileSync(variantPaths[testCase.name], join(root, "latest.json"));
      }
      const state = { app, root };
      const result = await runCase(testCase, state);
      results.push({ name: testCase.name, ...result });
      console.log(
        `${result.ok ? "[ OK ]" : "[FAIL]"} ${testCase.name} ${result.elapsedMs}ms` +
          (result.ok ? ` event=${result.record.event}` : " 未命中预期事件"),
      );
      if (!result.ok) {
        const tail = result.records.slice(-5).map((item) => `${item.event}:${item.code ?? "-"}`);
        console.log(`       最近事件: ${tail.join(" | ") || "<无>"}`);
      }
    }
  } finally {
    writeFileSync(join(root, "latest.json"), originalManifest);
    stopClient();
  }

  const positive = runnable.some((item) => item.positive) ? results.find((item) => item.name === "positive") : null;
  let versionMismatch = false;
  if (positive?.ok) {
    const actual = installedVersion(app);
    console.log(`\n[ CHECK ] 安装后版本: ${actual || "<未知>"}，期望 ${version}`);
    versionMismatch = actual !== version;
    if (versionMismatch) console.error("[FAIL] 安装后版本与清单不一致");
  }

  const failed = results.filter((item) => !item.ok);
  console.log(`\n[SUMMARY] ${results.length - failed.length}/${results.length} 通过`);
  if (failed.length > 0 || versionMismatch) process.exit(1);
}

main().catch((error) => {
  console.error(`[FAIL] ${error.stack ?? error.message}`);
  process.exit(1);
});
