/*
 * 生成发布物料账本。
 *
 * 账本把安装包、签名、SBOM 与清单的哈希绑定到同一发布标识，供审计与回滚
 * 复核。脚本只读取已有文件并计算哈希，不修改任何发布物料。
 */
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { spawnSync } from "node:child_process";

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

function sha256(path) {
  return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function readFileVersion(path) {
  if (process.platform !== "win32") return "";
  const script = "(Get-Item -LiteralPath $env:VERTHYS_FILE).VersionInfo.FileVersion";
  for (const shell of ["powershell.exe", "pwsh.exe"]) {
    const result = spawnSync(shell, ["-NoProfile", "-NonInteractive", "-Command", script], {
      encoding: "utf8",
      timeout: 15000,
      windowsHide: true,
      env: { ...process.env, VERTHYS_FILE: path },
    });
    if (!result.error && result.status === 0 && result.stdout.trim()) {
      return result.stdout.trim();
    }
  }
  return "";
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  const required = ["release-id", "version", "channel", "installer"];
  for (const key of required) {
    if (!args[key]?.trim()) fail(`缺少参数 --${key}`);
  }

  const installer = resolve(args.installer);
  if (!existsSync(installer)) fail(`安装包不存在: ${installer}`);
  const signaturePath = args.signature ? resolve(args.signature) : `${installer}.sig`;
  if (!existsSync(signaturePath)) fail(`签名不存在: ${signaturePath}`);
  const manifestPath = args.manifest ? resolve(args.manifest) : "";
  if (manifestPath && !existsSync(manifestPath)) fail(`清单不存在: ${manifestPath}`);
  const sbomPath = args.sbom ? resolve(args.sbom) : "";
  if (sbomPath && !existsSync(sbomPath)) fail(`SBOM 不存在: ${sbomPath}`);
  const outPath = args.out
    ? resolve(args.out)
    : resolve(dirname(installer), "release-manifest.json");

  const installerSha = sha256(installer);
  const fileVersion = readFileVersion(installer);
  const payload = {
    schema_version: 1,
    release_id: args["release-id"],
    version: args.version,
    channels: [args.channel],
    git_tag: args["git-tag"] ?? "",
    git_commit: args["git-commit"] ?? "",
    build_profile: args.profile ?? "local",
    built_at: new Date().toISOString(),
    builder: args.builder ?? "",
    installer: {
      path: installer,
      sha256: installerSha,
      size: statSync(installer).size,
      file_version: fileVersion,
      minisign_sha256: sha256(signaturePath),
    },
    sbom: sbomPath
      ? { path: sbomPath, sha256: sha256(sbomPath) }
      : null,
    manifests: manifestPath
      ? [
          {
            channel: args.channel,
            revision: args["manifest-revision"] ?? "",
            path: manifestPath,
            sha256: sha256(manifestPath),
          },
        ]
      : [],
    approvals: [],
  };

  mkdirSync(dirname(outPath), { recursive: true });
  const tempPath = `${outPath}.tmp`;
  writeFileSync(tempPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  renameSync(tempPath, outPath);
  console.log(`[ OK ] release manifest: ${outPath}`);
  console.log(`[ OK ] installer sha256: ${installerSha}`);
  console.log(`[ OK ] file version: ${fileVersion || "<unknown>"}`);
}

main();
