/*
 * 更新源站缓存契约检查。
 *
 * CDN 回源行为依赖源站正确声明缓存与校验头：清单必须每次回源，安装包必须
 * 长期不可变缓存并支持条件请求与范围请求。脚本只探测已运行的回环服务，
 * 不修改任何物料。
 *
 * 用法:
 *   node scripts/updater/check_updater_origin.mjs [--url http://127.0.0.1:8765]
 */
const DEFAULT_BASE = "http://127.0.0.1:8765";

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

function header(response, name) {
  return response.headers.get(name) ?? "";
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log("用法: node scripts/updater/check_updater_origin.mjs [--url http://127.0.0.1:8765]");
    return;
  }
  const base = new URL(args.url ?? DEFAULT_BASE);
  const manifestUrl = new URL("latest.json", base);

  const manifestResponse = await fetch(manifestUrl, { cache: "no-store" });
  if (!manifestResponse.ok) fail(`清单不可访问: ${manifestResponse.status}`);
  const manifestCache = header(manifestResponse, "cache-control");
  if (!manifestCache.includes("no-store")) {
    fail(`清单必须 no-store，当前为: ${manifestCache || "<空>"}`);
  }
  const manifest = await manifestResponse.json();
  const platform = manifest?.platforms?.["windows-x86_64"];
  if (!platform?.url) fail("清单缺少 windows-x86_64 下载地址");
  const installerUrl = new URL(platform.url, base);

  const head = await fetch(installerUrl, { method: "HEAD" });
  if (!head.ok) fail(`安装包不可访问: ${head.status}`);
  const installerCache = header(head, "cache-control");
  if (!installerCache.includes("immutable") || !installerCache.includes("max-age=31536000")) {
    fail(`安装包缓存策略不合规: ${installerCache || "<空>"}`);
  }
  if (header(head, "accept-ranges") !== "bytes") {
    fail("安装包未声明字节范围支持");
  }
  const etag = header(head, "etag");
  if (!etag) fail("安装包缺少 ETag");
  const size = Number(header(head, "content-length"));
  if (!Number.isInteger(size) || size <= 0) fail("安装包长度非法");

  const cached = await fetch(installerUrl, {
    headers: { "If-None-Match": etag },
  });
  if (cached.status !== 304) fail(`条件请求应返回 304，当前为: ${cached.status}`);

  const ranged = await fetch(installerUrl, {
    headers: { Range: "bytes=0-99" },
  });
  if (ranged.status !== 206) fail(`范围请求应返回 206，当前为: ${ranged.status}`);
  const contentRange = header(ranged, "content-range");
  if (!contentRange.startsWith(`bytes 0-99/${size}`)) {
    fail(`范围响应头不正确: ${contentRange || "<空>"}`);
  }
  const body = new Uint8Array(await ranged.arrayBuffer());
  if (body.length !== 100) fail(`范围响应长度应为 100，当前为: ${body.length}`);

  const unsatisfiable = await fetch(installerUrl, {
    headers: { Range: `bytes=${size}-` },
  });
  if (unsatisfiable.status !== 416) {
    fail(`越界范围应返回 416，当前为: ${unsatisfiable.status}`);
  }
  if (!header(unsatisfiable, "content-range").startsWith(`bytes */${size}`)) {
    fail("越界范围的 Content-Range 不正确");
  }

  console.log(`[ OK ] 清单 no-store: ${manifest.version}`);
  console.log(`[ OK ] 安装包 immutable + ETag + 304`);
  console.log(`[ OK ] 安装包 Range 206 / 416`);
}

main().catch((error) => {
  console.error(`[FAIL] ${error.stack ?? error.message}`);
  process.exit(1);
});
