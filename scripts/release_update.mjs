/**
 * 生成一次可发布的更新物料目录。
 *
 * 输入真实 NSIS 安装包与其 minisign 签名，输出：签名清单、安装包副本、账本。
 * 所有步骤串行执行；任一步失败即停止，不产生半成品目录。
 */
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const node = process.execPath;

function fail(message) {
  console.error(`[FAIL] ${message}`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i];
    if (!raw.startsWith("--")) fail(`无法识别的参数: ${raw}`);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) fail(`参数缺少取值: ${raw}`);
    args[raw.slice(2)] = value;
    i++;
  }
  return args;
}

/**
 * 读取安装包的 Authenticode 状态。
 *
 * 非 Windows 或 PowerShell 不可用时返回空串，由调用方按失败处理；生产渠道
 * 不允许在无法证明系统信任链的情况下生成物料。
 */
function authenticodeStatus(path) {
  if (process.platform !== "win32") return "";
  const script = "(Get-AuthenticodeSignature -LiteralPath $env:VERTHYS_AUTH_FILE).Status";
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    encoding: "utf8",
    timeout: 60000,
    windowsHide: true,
    env: { ...process.env, VERTHYS_AUTH_FILE: path },
  });
  return result.status === 0 ? result.stdout.trim() : "";
}

function run(script, args) {
  const result = spawnSync(node, [resolve(root, "scripts", script), ...args], {
    encoding: "utf8",
    timeout: 120000,
  });
  if (result.stdout?.trim()) console.log(result.stdout.trim());
  if (result.stderr?.trim()) console.error(result.stderr.trim());
  if (result.error || result.status !== 0) {
    fail(`${script} 执行失败`);
  }
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const installer = resolve(args.installer ?? "");
  if (!args.installer || !existsSync(installer)) fail(`安装包不存在: ${installer}`);
  const signature = resolve(args.signature ?? `${installer}.sig`);
  if (!existsSync(signature)) fail(`安装包签名不存在: ${signature}`);
  const endpoint = (args.endpoint ?? "").trim();
  let endpointUrl;
  try {
    endpointUrl = new URL(endpoint);
  } catch {
    fail(`--endpoint 不是合法 URL: ${endpoint || "<空>"}`);
  }
  const version = (args.version ?? readFileSync(resolve(root, "VERSION"), "utf8")).trim();
  if (!/^\d+\.\d+\.\d+$/.test(version)) fail(`版本号非法: ${version}`);
  const channel = (args.channel ?? "stable").trim();
  if (!["local", "internal", "beta", "stable"].includes(channel)) {
    fail(`渠道非法: ${channel}`);
  }
  const profile = (args.profile ?? "production").trim();
  if (channel !== "local") {
    const status = authenticodeStatus(installer);
    if (status !== "Valid") {
      fail(`生产渠道安装包未通过 Authenticode 系统信任校验: ${status || "<未知>"}`);
    }
    console.log("[ OK ] Authenticode 系统信任校验通过");
  }
  const notes = (args.notes ?? `Verthys ${version} 更新`).trim();
  const compatArgs = [];
  for (const key of [
    "compat-abi-min",
    "compat-abi-max",
    "compat-container-min",
    "compat-container-max",
  ]) {
    if (args[key]) compatArgs.push(`--${key}`, args[key]);
  }
  const outRoot = resolve(args.out ?? resolve(root, "build", "updater", "releases"));
  mkdirSync(outRoot, { recursive: true });

  const installerName = installer.split(/[\\/]/).pop();
  const installerUrl = new URL(installerName, endpointUrl).toString();
  const staging = resolve(outRoot, `.staging-${randomUUID()}`);
  mkdirSync(staging, { recursive: true });
  const stagingManifest = resolve(staging, "latest.json");

  try {
    run("make_updater_manifest.mjs", [
      "--version",
      version,
      "--installer",
      installer,
      "--signature",
      signature,
      "--url",
      installerUrl,
      "--notes",
      notes,
      "--channel",
      channel,
      "--out",
      stagingManifest,
      ...compatArgs,
    ]);

    const manifest = JSON.parse(readFileSync(stagingManifest, "utf8"));
    const releaseId = String(manifest.release_id ?? "").trim();
    if (!releaseId) fail("清单缺少 release_id");

    const finalDir = resolve(outRoot, releaseId);
    mkdirSync(finalDir, { recursive: true });
    const finalManifest = resolve(finalDir, "latest.json");
    renameSync(stagingManifest, finalManifest);
    const finalInstaller = resolve(finalDir, installerName);
    const finalSignature = `${finalInstaller}.sig`;
    copyFileSync(installer, finalInstaller);
    copyFileSync(signature, finalSignature);

    run("sign_manifest.mjs", [finalManifest]);

    const sbom = resolve(root, "build", "sbom.cdx.json");
    const ledgerArgs = [
      "--release-id",
      releaseId,
      "--version",
      version,
      "--channel",
      channel,
      "--installer",
      finalInstaller,
      "--manifest",
      finalManifest,
      "--profile",
      profile,
      "--out",
      resolve(finalDir, "release-manifest.json"),
    ];
    if (existsSync(sbom)) {
      ledgerArgs.push("--sbom", sbom);
    }
    run("generate_release_manifest.mjs", ledgerArgs);

    writeFileSync(
      resolve(finalDir, "channel-pointer.json"),
      `${JSON.stringify({ channel, releaseId, manifest: "latest.json" }, null, 2)}\n`,
    );
    if (channel === "local") {
      // 本机回环服务固定读取 build/updater/latest.json 与同目录安装包。
      const publishDir = resolve(root, "build", "updater");
      mkdirSync(publishDir, { recursive: true });
      copyFileSync(finalManifest, resolve(publishDir, "latest.json"));
      copyFileSync(finalInstaller, resolve(publishDir, installerName));
      copyFileSync(finalSignature, resolve(publishDir, `${installerName}.sig`));
    }
    console.log(`[ OK ] 更新发布物料: ${finalDir}`);
  } catch (error) {
    rmSync(staging, { recursive: true, force: true });
    throw error;
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

main();
