/**
 * 校验 Tauri 更新有效配置（基础配置 + profile 覆盖层）是否合规。
 *
 * production 要求全链路 HTTPS、非回环、非占位主机且禁止明文开关；local 只允许回环。
 * 只解析 plugins.updater，不解释其余配置；合并语义与 Tauri 的覆盖层一致：对象深合并、
 * 数组整体替换。
 */
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const PROFILES = new Set(["production", "local"]);

function fail(message) {
  console.error(`[FAIL] ${message}`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = { positional: [] };
  for (let i = 0; i < argv.length; i++) {
    const raw = argv[i];
    if (raw === "--help" || raw === "-h") {
      args.help = true;
      continue;
    }
    if (raw.startsWith("--")) {
      const key = raw.slice(2);
      if (key === "allow-insecure") {
        args.allowInsecure = true;
        continue;
      }
      const value = argv[i + 1];
      if (value === undefined || value.startsWith("--")) fail(`参数缺少取值: ${raw}`);
      if (!["profile", "endpoint", "allow-insecure", "base"].includes(key)) {
        fail(`无法识别的参数: ${raw}`);
      }
      args[key] = value;
      i++;
      continue;
    }
    args.positional.push(raw);
  }
  return args;
}

function isObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function deepMerge(base, overlay) {
  if (!isObject(base) || !isObject(overlay)) return overlay;
  const result = { ...base };
  for (const [key, value] of Object.entries(overlay)) {
    result[key] =
      isObject(value) && isObject(result[key]) ? deepMerge(result[key], value) : value;
  }
  return result;
}

function isLoopbackHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return host === "localhost" || host === "::1" || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

function isPlaceholderHost(hostname) {
  const host = hostname.toLowerCase();
  return (
    isLoopbackHost(host) ||
    host === "example.com" ||
    host.endsWith(".example") ||
    host.endsWith(".invalid") ||
    host.endsWith(".test")
  );
}

function readJson(path, label) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`无法读取或解析${label} ${path}: ${error.message}`);
  }
}

function printHelp() {
  console.log(
    [
      "用法:",
      "  node scripts/gates/check_updater_profile.mjs <overlay.json> --profile production|local [--endpoint <url>] [--allow-insecure] [--base <tauri.conf.json>]",
      "",
      "默认与覆盖层同目录的 tauri.conf.json 深合并；--base 可显式指定基础配置。",
      "production 可用 --endpoint 注入真实端点；仍指向占位主机或回环会失败。",
      "production 使用 http 端点时必须显式传入 --allow-insecure。",
      "local 要求回环端点；http 端点必须显式开启明文传输许可。",
    ].join("\n"),
  );
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printHelp();
    return;
  }
  if (args.positional.length !== 1) fail("必须提供且只提供一个 profile 覆盖层路径");

  const profile = (args.profile ?? "").trim();
  if (!PROFILES.has(profile)) {
    fail(`--profile 必须是 production 或 local，当前为: ${profile || "<空>"}`);
  }

  const overlayPath = resolve(args.positional[0]);
  const basePath = args.base
    ? resolve(args.base)
    : resolve(dirname(overlayPath), "tauri.conf.json");
  const base = readJson(basePath, "基础配置");
  const overlay = readJson(overlayPath, "profile 覆盖层");
  if (!isObject(base) || !isObject(overlay)) fail("配置根节点必须是对象");

  const config = deepMerge(base, overlay);
  if (!isObject(config.plugins) || !isObject(config.plugins.updater)) {
    fail("合并后的 plugins.updater 缺失或不是对象");
  }
  const updater = config.plugins.updater;
  if (args.allowInsecure) {
    if (profile !== "production") fail("--allow-insecure 仅用于 production");
    updater.dangerousInsecureTransportProtocol = true;
  }

  if (args.endpoint !== undefined) {
    if (profile !== "production") fail("--endpoint 仅用于 production");
    const endpoint = args.endpoint.trim();
    let url;
    try {
      url = new URL(endpoint);
    } catch {
      fail(`--endpoint 不是合法 URL: ${endpoint}`);
    }
    const allowInsecure = updater.dangerousInsecureTransportProtocol === true;
    if (url.protocol !== "https:" && !(url.protocol === "http:" && allowInsecure)) {
      fail("--endpoint 必须使用 https（或显式开启明文许可）");
    }
    const host = url.hostname.toLowerCase();
    updater.endpoints = [endpoint];
    const existingHosts = Array.isArray(updater.allowedDownloadHosts)
      ? updater.allowedDownloadHosts.filter(
          (item) => typeof item === "string" && !isPlaceholderHost(item),
        )
      : [];
    updater.allowedDownloadHosts = [
      host,
      ...existingHosts.filter((item) => item.toLowerCase() !== host),
    ];
  }

  const endpoints = updater.endpoints;
  if (!Array.isArray(endpoints)) fail("plugins.updater.endpoints 必须是数组");
  const insecure = updater.dangerousInsecureTransportProtocol;
  if (insecure !== undefined && typeof insecure !== "boolean") {
    fail("plugins.updater.dangerousInsecureTransportProtocol 必须是布尔值");
  }
  const channel = updater.channel;
  if (typeof channel !== "string" || !channel.trim()) {
    fail("plugins.updater.channel 缺失或不是字符串");
  }
  if (profile === "local" && channel !== "local") {
    fail(`local profile 的 channel 必须是 local，当前为 ${channel}`);
  }
  if (profile !== "local" && channel === "local") {
    fail("production profile 不得使用 local channel");
  }

  const authenticode = updater.authenticode;
  if (!isObject(authenticode)) {
    fail("plugins.updater.authenticode 缺失或不是对象");
  }
  if (typeof authenticode.require !== "boolean") {
    fail("plugins.updater.authenticode.require 必须是布尔值");
  }
  if (authenticode.revocation !== undefined && typeof authenticode.revocation !== "boolean") {
    fail("plugins.updater.authenticode.revocation 必须是布尔值");
  }
  if (profile === "local" && authenticode.require !== false) {
    fail("local profile 必须关闭 Authenticode，避免未签名开发物料被误拒");
  }
  if (authenticode.subject !== undefined && typeof authenticode.subject !== "string") {
    fail("plugins.updater.authenticode.subject 必须是字符串");
  }
  if (
    typeof authenticode.thumbprint === "string" &&
    authenticode.thumbprint.replace(/[\s:]/g, "")
  ) {
    const thumbprint = authenticode.thumbprint.replace(/[\s:]/g, "");
    if (!/^[0-9a-fA-F]{40}$/.test(thumbprint)) {
      fail("plugins.updater.authenticode.thumbprint 必须是 40 位十六进制");
    }
  }

  const violations = [];
  if (endpoints.length === 0) violations.push("plugins.updater.endpoints 不能为空");

  endpoints.forEach((endpoint, index) => {
    const label = `plugins.updater.endpoints[${index}]`;
    if (typeof endpoint !== "string" || !endpoint.trim()) {
      violations.push(`${label} 必须是非空字符串`);
      return;
    }
    let url;
    try {
      url = new URL(endpoint);
    } catch {
      violations.push(`${label} 不是合法 URL: ${endpoint}`);
      return;
    }

    if (profile === "production") {
      const insecureHttp = url.protocol === "http:" && insecure === true;
      if (url.protocol !== "https:" && !insecureHttp) {
        violations.push(
          `${label} 必须使用 https（或显式开启明文许可），当前为 ${url.protocol}`,
        );
      }
      if (isPlaceholderHost(url.hostname)) {
        violations.push(`${label} 仍是占位或回环主机: ${url.hostname}`);
      }
      return;
    }

    if (url.protocol !== "http:" && url.protocol !== "https:") {
      violations.push(`${label} 必须使用 http 或 https，当前为 ${url.protocol}`);
    }
    if (!isLoopbackHost(url.hostname)) {
      violations.push(`${label} 必须使用回环地址，当前主机为 ${url.hostname || "<空>"}`);
    }
    if (url.protocol === "http:" && insecure !== true) {
      violations.push(`${label} 使用 http 时必须显式开启明文传输许可`);
    }
  });

  const downloadHosts = updater.allowedDownloadHosts;
  if (downloadHosts !== undefined) {
    if (!Array.isArray(downloadHosts) || downloadHosts.some((host) => typeof host !== "string")) {
      violations.push("plugins.updater.allowedDownloadHosts 必须是字符串数组");
    } else if (profile === "production") {
      for (const host of downloadHosts) {
        if (isPlaceholderHost(host)) {
          violations.push(`allowedDownloadHosts 仍包含占位或回环主机: ${host}`);
        }
      }
    }
  }

  if (violations.length > 0) {
    for (const item of violations) console.error(`[FAIL] ${item}`);
    process.exit(1);
  }

  console.log(`[ OK ] profile=${profile} 有效配置合规: ${overlayPath}`);
}

main();
