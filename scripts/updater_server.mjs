/**
 * 本机更新静态服务。
 *
 * 仅绑定回环地址，只提供更新清单、安装包与签名三类文件，用于本机端到端验证。
 * 路径解析先解码再规范化，并以真实路径做根目录包含校验，阻断目录穿越与符号链接逃逸。
 */
import { createReadStream, existsSync, realpathSync, statSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, extname, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");
const DEFAULT_ROOT = resolve(REPO_ROOT, "build", "updater");
const BIND_HOST = "127.0.0.1";
const ALLOWED_EXT = new Set([".json", ".exe", ".sig", ".txt"]);
const CONTENT_TYPE = {
  ".json": "application/json; charset=utf-8",
  ".exe": "application/octet-stream",
  ".sig": "text/plain; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

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
      "  node scripts/updater_server.mjs [--root build/updater] [--port 8765]",
      "",
      "服务固定绑定 127.0.0.1，不提供局域网访问选项。",
    ].join("\n"),
  );
  process.exit(0);
}

const rootArg = args.root ? resolve(args.root) : DEFAULT_ROOT;
if (!existsSync(rootArg) || !statSync(rootArg).isDirectory()) {
  fail(`服务目录不存在或不是目录: ${rootArg}`);
}
const rootReal = realpathSync(rootArg);

const port = args.port === undefined ? 8765 : Number(args.port);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  fail(`端口不合法: ${args.port}`);
}

function logLine(status, method, pathname, bytes) {
  const time = new Date().toISOString();
  console.log(`${time} ${method} ${pathname} ${status} ${bytes}`);
}

const server = createServer((req, res) => {
  const method = req.method ?? "GET";

  if (method !== "GET" && method !== "HEAD") {
    res.writeHead(405, { Allow: "GET, HEAD" });
    res.end();
    logLine(405, method, req.url ?? "-", 0);
    return;
  }

  let pathname;
  try {
    pathname = decodeURIComponent(new URL(req.url ?? "/", `http://${BIND_HOST}`).pathname);
  } catch {
    res.writeHead(400);
    res.end();
    logLine(400, method, req.url ?? "-", 0);
    return;
  }

  if (pathname.includes("\0") || pathname.includes("..")) {
    res.writeHead(400);
    res.end();
    logLine(400, method, pathname, 0);
    return;
  }
  if (pathname === "/" || pathname.endsWith("/")) {
    res.writeHead(404);
    res.end();
    logLine(404, method, pathname, 0);
    return;
  }

  const candidate = resolve(rootReal, `.${pathname}`);
  if (candidate !== rootReal && !candidate.startsWith(rootReal + sep)) {
    res.writeHead(403);
    res.end();
    logLine(403, method, pathname, 0);
    return;
  }
  if (!ALLOWED_EXT.has(extname(candidate).toLowerCase())) {
    res.writeHead(404);
    res.end();
    logLine(404, method, pathname, 0);
    return;
  }

  let realFile;
  let size;
  try {
    realFile = realpathSync(candidate);
    const stat = statSync(realFile);
    if (!stat.isFile()) throw new Error("not a file");
    size = stat.size;
  } catch {
    res.writeHead(404);
    res.end();
    logLine(404, method, pathname, 0);
    return;
  }

  if (realFile !== rootReal && !realFile.startsWith(rootReal + sep)) {
    res.writeHead(403);
    res.end();
    logLine(403, method, pathname, 0);
    return;
  }

  const headers = {
    "Content-Type": CONTENT_TYPE[extname(realFile).toLowerCase()],
    "Content-Length": String(size),
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
  };

  res.writeHead(200, headers);
  if (method === "HEAD") {
    res.end();
    logLine(200, method, pathname, 0);
    return;
  }

  const stream = createReadStream(realFile);
  stream.on("error", () => res.destroy());
  stream.pipe(res);
  logLine(200, method, pathname, size);
});

server.on("error", (error) => {
  fail(`服务启动失败: ${error.message}`);
});

server.listen(port, BIND_HOST, () => {
  console.log(`[ OK ] 更新服务已启动: http://${BIND_HOST}:${port}/`);
  console.log(`[ OK ] 服务目录: ${rootReal}`);
  console.log("[ OK ] 仅接受回环地址访问，按 Ctrl+C 停止");
});

function shutdown(signal) {
  console.log(`[INFO] 收到 ${signal}，正在关闭服务`);
  server.close(() => process.exit(0));
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));
