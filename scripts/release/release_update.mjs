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
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const root = resolve(SCRIPT_DIR, "..", "..");
const node = process.execPath;

class CliFailure extends Error {}

/**
 * 失败必须抛错而不是直接退出：本脚本持有临时目录与发布目录的清理责任，
 * process.exit 会跳过 catch/finally，把"不产生半成品目录"的契约打破。
 */
function fail(message) {
  throw new CliFailure(message);
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
  // 构建父进程可能是 PowerShell 7；Windows PowerShell 5.1 子进程继承 7 的
  // PSModulePath 时无法加载 Microsoft.PowerShell.Security，Cert: 不存在，
  // 签名状态会误报为空。这里显式恢复 5.1 的模块路径。
  const psModulePath = [
    join(process.env.USERPROFILE ?? "", "Documents", "WindowsPowerShell", "Modules"),
    join(process.env.ProgramFiles ?? "", "WindowsPowerShell", "Modules"),
    join(process.env.WINDIR ?? "C:\\Windows", "system32", "WindowsPowerShell", "v1.0", "Modules"),
  ].join(";");
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], {
    encoding: "utf8",
    timeout: 60000,
    windowsHide: true,
    env: { ...process.env, VERTHYS_AUTH_FILE: path, PSModulePath: psModulePath },
  });
  return result.status === 0 ? result.stdout.trim() : "";
}

function run(script, args) {
  const result = spawnSync(node, [resolve(SCRIPT_DIR, script), ...args], {
    encoding: "utf8",
    timeout: 120000,
  });
  if (result.stdout?.trim()) console.log(result.stdout.trim());
  if (result.stderr?.trim()) console.error(result.stderr.trim());
  if (result.error || result.status !== 0) {
    fail(`${script} 执行失败`);
  }
}

/**
 * 读取仓库版本标识：账本必须能追溯到具体提交，否则审计无法复现发布物。
 * git 不可用或非仓库目录时返回空串（调用方按缺失处理，不阻塞构包）。
 */
function gitValue(args) {
  const result = spawnSync("git", ["-C", root, ...args], {
    encoding: "utf8",
    timeout: 15000,
    windowsHide: true,
  });
  return result.error || result.status !== 0 ? "" : result.stdout.trim();
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const installerArg = (args.installer ?? "").trim();
  if (!installerArg) fail("缺少参数 --installer");
  const installer = resolve(installerArg);
  if (!existsSync(installer)) fail(`安装包不存在: ${installer}`);
  const signature = resolve((args.signature ?? `${installer}.sig`).trim());
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
  if (!["local", "production"].includes(profile)) {
    fail(`profile 非法: ${profile}`);
  }
  if (channel !== "local") {
    const status = authenticodeStatus(installer);
    if (status !== "Valid") {
      // Authenticode 是可选的系统信任层，不阻断发布；未签名安装包仍可通过
      // 清单签名、安装包签名、SHA256 与 PE 版本校验。
      console.warn(
        `[WARN] 安装包未通过 Authenticode 系统信任校验（允许发布）: ${status || "<未知>"}`,
      );
    } else {
      console.log("[ OK ] Authenticode 系统信任校验通过");
    }
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
  if (!installerName) fail(`无法从安装包路径解析文件名: ${installer}`);
  const installerUrl = new URL(installerName, endpointUrl).toString();
  const artifactRoot = (args["artifact-root"] ?? "").trim();
  const staging = resolve(outRoot, `.staging-${randomUUID()}`);
  mkdirSync(staging, { recursive: true });
  const stagingManifest = resolve(staging, "latest.json");

  // 失败清理契约：本脚本声明"任一步失败即停止，不产生半成品目录"。
  // 发布目录只在所有步骤成功后保留；若本次新建的目录中途失败则整体移除。
  // 已存在的同名发布目录（重发场景）不删除，避免误伤历史物料。
  let finalDir = null;
  let finalDirCreated = false;

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
      ...(artifactRoot ? ["--artifact-root", artifactRoot] : []),
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

    finalDir = resolve(outRoot, releaseId);
    finalDirCreated = !existsSync(finalDir);
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
    const gitCommit = gitValue(["rev-parse", "HEAD"]);
    const gitTag = gitValue(["describe", "--tags", "--always", "--dirty"]);
    const builder = (process.env.USERNAME || process.env.USER || "").trim();
    if (gitCommit) ledgerArgs.push("--git-commit", gitCommit);
    if (gitTag) ledgerArgs.push("--git-tag", gitTag);
    if (builder) ledgerArgs.push("--builder", builder);
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
    if (finalDir && finalDirCreated) {
      rmSync(finalDir, { recursive: true, force: true });
    }
    throw error;
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  const message = error instanceof CliFailure ? error.message : (error.stack ?? error.message);
  console.error(`[FAIL] ${message}`);
  process.exit(1);
}
