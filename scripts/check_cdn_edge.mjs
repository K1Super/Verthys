/*
 * CDN 边缘缓存与回源模拟检查。
 *
 * 真实 CDN 不可用时，用本进程内的边缘代理验证回源契约：清单必须每次回源，
 * 安装包命中边缘缓存，Range 与条件请求由缓存直接应答。代理只监听回环地址，
 * 不修改物料。
 *
 * 用法:
 *   node scripts/check_cdn_edge.mjs [--root build/updater]
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer, request } from "node:http";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(SCRIPT_DIR, "..");
const HOST = "127.0.0.1";

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
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) fail(`参数缺少取值: ${raw}`);
    args[raw.slice(2)] = value;
    i++;
  }
  return args;
}

function freePort() {
  return new Promise((resolvePort, reject) => {
    const server = createServer();
    server.listen(0, HOST, () => {
      const port = server.address().port;
      server.close(() => resolvePort(port));
    });
    server.on("error", reject);
  });
}

function waitForOrigin(port, timeoutMs = 10000) {
  const deadline = Date.now() + timeoutMs;
  return new Promise((resolveWait, reject) => {
    const tick = async () => {
      try {
        const response = await fetch(`http://${HOST}:${port}/latest.json`);
        if (response.ok) {
          resolveWait();
          return;
        }
      } catch {
        // 服务尚未监听，继续等待。
      }
      if (Date.now() > deadline) {
        reject(new Error("回环服务启动超时"));
        return;
      }
      setTimeout(tick, 200);
    };
    tick();
  });
}

function fetchOrigin(port, pathname, method = "GET", headers = {}) {
  return new Promise((resolveFetch, reject) => {
    const req = request(
      { host: HOST, port, path: pathname, method, headers },
      (response) => {
        const chunks = [];
        response.on("data", (chunk) => chunks.push(chunk));
        response.on("end", () =>
          resolveFetch({
            status: response.statusCode ?? 0,
            headers: response.headers,
            body: Buffer.concat(chunks),
          }),
        );
      },
    );
    req.on("error", reject);
    req.end();
  });
}

function parseRange(header, size) {
  if (!header) return null;
  const match = /^bytes=(\d*)-(\d*)$/.exec(header.trim());
  if (!match) return null;
  let start;
  let end;
  if (match[1] === "") {
    const suffix = Number(match[2]);
    if (!Number.isInteger(suffix) || suffix <= 0) return { invalid: true };
    start = Math.max(0, size - suffix);
    end = size - 1;
  } else {
    start = Number(match[1]);
    end = match[2] === "" ? size - 1 : Number(match[2]);
  }
  if (
    !Number.isInteger(start) ||
    !Number.isInteger(end) ||
    start < 0 ||
    end < start ||
    start >= size
  ) {
    return { invalid: true };
  }
  return { start, end: Math.min(end, size - 1) };
}

function serveCached(req, res, entry) {
  const headers = { ...entry.headers };
  delete headers["content-length"];
  const etag = headers.etag;
  const ifNoneMatch = (req.headers["if-none-match"] ?? "").split(",").map((item) => item.trim());
  if (etag && ifNoneMatch.includes(etag)) {
    res.writeHead(304, headers);
    res.end();
    return;
  }
  const range = parseRange(req.headers.range, entry.body.length);
  if (range?.invalid) {
    res.writeHead(416, { ...headers, "Content-Range": `bytes */${entry.body.length}` });
    res.end();
    return;
  }
  if (range) {
    const length = range.end - range.start + 1;
    res.writeHead(206, {
      ...headers,
      "Content-Length": String(length),
      "Content-Range": `bytes ${range.start}-${range.end}/${entry.body.length}`,
    });
    res.end(entry.body.subarray(range.start, range.end + 1));
    return;
  }
  res.writeHead(entry.status, { ...headers, "Content-Length": String(entry.body.length) });
  res.end(entry.body);
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log("用法: node scripts/check_cdn_edge.mjs [--root build/updater]");
    return;
  }
  const root = resolve(args.root ?? join(REPO_ROOT, "build", "updater"));
  if (!existsSync(join(root, "latest.json"))) fail(`清单不存在: ${join(root, "latest.json")}`);

  const originPort = await freePort();
  const edgePort = await freePort();
  const origin = spawn(process.execPath, [
    join(SCRIPT_DIR, "updater_server.mjs"),
    "--root",
    root,
    "--port",
    String(originPort),
  ], { stdio: "ignore", windowsHide: true });

  const cache = new Map();
  const originFetches = {};
  const edgeHits = {};
  const isManifest = (pathname) => pathname.endsWith(".json") || pathname.endsWith(".txt");

  const edge = createServer(async (req, res) => {
    try {
      const pathname = new URL(req.url ?? "/", `http://${HOST}`).pathname;
      if (req.method === "GET" && !isManifest(pathname) && cache.has(pathname)) {
        edgeHits[pathname] = (edgeHits[pathname] ?? 0) + 1;
        serveCached(req, res, cache.get(pathname));
        return;
      }
      originFetches[pathname] = (originFetches[pathname] ?? 0) + 1;
      const upstream = await fetchOrigin(originPort, pathname, req.method, req.headers);
      if (req.method === "GET" && upstream.status === 200 && !isManifest(pathname)) {
        cache.set(pathname, {
          status: upstream.status,
          headers: upstream.headers,
          body: upstream.body,
        });
      }
      const headers = { ...upstream.headers };
      delete headers["content-length"];
      res.writeHead(upstream.status, {
        ...headers,
        "Content-Length": String(upstream.body.length),
      });
      res.end(upstream.body);
    } catch (error) {
      res.writeHead(502);
      res.end(String(error));
    }
  });

  try {
    await waitForOrigin(originPort);
    await new Promise((resolveListen) => edge.listen(edgePort, HOST, resolveListen));

    const manifestUrl = `http://${HOST}:${edgePort}/latest.json`;
    const firstManifest = await fetch(manifestUrl);
    const secondManifest = await fetch(manifestUrl);
    assert.equal(firstManifest.status, 200);
    assert.equal(secondManifest.status, 200);
    assert.match(firstManifest.headers.get("cache-control") ?? "", /no-store/);
    assert.equal(originFetches["/latest.json"], 2, "清单必须每次回源");
    const manifest = await firstManifest.json();
    const installerUrl = new URL(manifest.platforms["windows-x86_64"].url);
    const installerPath = installerUrl.pathname;

    const firstInstaller = await fetch(`http://${HOST}:${edgePort}${installerPath}`);
    const firstBody = Buffer.from(await firstInstaller.arrayBuffer());
    const secondInstaller = await fetch(`http://${HOST}:${edgePort}${installerPath}`);
    await secondInstaller.arrayBuffer();
    assert.equal(firstInstaller.status, 200);
    assert.equal(originFetches[installerPath], 1, "安装包首次应回源");
    assert.equal(edgeHits[installerPath], 1, "安装包第二次应命中边缘");
    assert.match(firstInstaller.headers.get("cache-control") ?? "", /immutable/);

    const etag = firstInstaller.headers.get("etag");
    assert.ok(etag, "安装包缺少 ETag");
    const notModified = await fetch(`http://${HOST}:${edgePort}${installerPath}`, {
      headers: { "If-None-Match": etag },
    });
    assert.equal(notModified.status, 304);
    assert.equal(originFetches[installerPath], 1, "条件请求不得回源");

    const ranged = await fetch(`http://${HOST}:${edgePort}${installerPath}`, {
      headers: { Range: "bytes=0-99" },
    });
    const rangedBody = Buffer.from(await ranged.arrayBuffer());
    assert.equal(ranged.status, 206);
    assert.equal(rangedBody.length, 100);
    assert.ok(rangedBody.equals(firstBody.subarray(0, 100)), "范围字节必须与源站一致");
    assert.equal(originFetches[installerPath], 1, "范围请求不得回源");

    console.log("[ OK ] 清单两次均回源且保持 no-store");
    console.log("[ OK ] 安装包首次回源、第二次命中边缘缓存");
    console.log("[ OK ] 条件请求 304 与范围请求 206 均由缓存应答");
  } finally {
    await new Promise((resolveClose) => edge.close(resolveClose));
    origin.kill();
  }
}

main().catch((error) => {
  console.error(`[FAIL] ${error.stack ?? error.message}`);
  process.exit(1);
});
