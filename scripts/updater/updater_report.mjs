/*
 * 更新发布报告生成器。
 *
 * 从本机 JSONL 事件日志聚合发布质量指标：检查命中、安装移交、健康结论、
 * 失败错误码与锁库耗时。报告只包含事件字段，不读取容器内容或用户数据。
 *
 * 用法:
 *   node scripts/updater/updater_report.mjs [--log-dir <目录>] [--out <json>] [--markdown <md>]
 */
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const APP_DATA = join(process.env.APPDATA ?? homedir(), "com.verthys.app");
const DEFAULT_DIRS = [join(APP_DATA, "logs", "updater"), join(APP_DATA, "updater", "logs")];

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

/** 读取目录内全部 JSONL；损坏行跳过，避免单行截断破坏整份报告。 */
export function readRecords(dirs) {
  const records = [];
  for (const dir of dirs) {
    if (!existsSync(dir)) continue;
    for (const name of readdirSync(dir)) {
      if (!name.endsWith(".jsonl")) continue;
      const path = join(dir, name);
      if (!statSync(path).isFile()) continue;
      for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
        if (!line.trim()) continue;
        try {
          const record = JSON.parse(line);
          if (record && typeof record === "object" && typeof record.event === "string") {
            records.push(record);
          }
        } catch {
          // 写入中断可能留下半行；报告只统计可解析事件。
        }
      }
    }
  }
  return records;
}

/** 聚合事件；健康阶段在新进程执行，指标按事件计数而不按会话拼接。 */
export function aggregate(records) {
  const sessions = new Set();
  const eventCounts = {};
  const failuresByCode = {};
  const toVersions = {};
  let totalDownloadedBytes = 0;
  let lockDurationSum = 0;
  let lockDurationCount = 0;

  for (const record of records) {
    const event = record.event;
    eventCounts[event] = (eventCounts[event] ?? 0) + 1;
    if (typeof record.sessionId === "string" && record.sessionId) {
      sessions.add(record.sessionId);
    }
    if (record.severity === "error" && typeof record.code === "string" && record.code) {
      failuresByCode[record.code] = (failuresByCode[record.code] ?? 0) + 1;
    }
    if (event === "download_success" && Number.isFinite(record.detail?.bytes)) {
      totalDownloadedBytes += record.detail.bytes;
    }
    if (event === "lock_ok" && Number.isFinite(record.detail?.durationMs)) {
      lockDurationSum += record.detail.durationMs;
      lockDurationCount += 1;
    }
    const toVersion = record.detail?.toVersion;
    if (event === "check_hit" && typeof toVersion === "string") {
      toVersions[toVersion] = (toVersions[toVersion] ?? 0) + 1;
    }
  }

  const count = (event) => eventCounts[event] ?? 0;
  const checks = count("check_sent");
  const hits = count("check_hit");
  const healthOk = count("health_ok");
  const healthFail = count("health_fail");

  return {
    generatedAt: new Date().toISOString(),
    totals: {
      sessions: sessions.size,
      checks,
      checkHits: hits,
      installHandoffs: count("install_handoff"),
      healthOk,
      healthFail,
      cancelled: count("cancelled"),
      downloadBytes: totalDownloadedBytes,
    },
    rates: {
      checkHitRate: checks > 0 ? hits / checks : null,
      healthSuccessRate:
        healthOk + healthFail > 0 ? healthOk / (healthOk + healthFail) : null,
    },
    lock: {
      averageDurationMs:
        lockDurationCount > 0 ? Math.round(lockDurationSum / lockDurationCount) : null,
    },
    eventCounts,
    failuresByCode,
    toVersions,
  };
}

export function toMarkdown(report) {
  const { totals, rates, lock } = report;
  const percent = (value) => (value === null ? "<无数据>" : `${(value * 100).toFixed(1)}%`);
  const lines = [
    "# 更新发布报告",
    "",
    `生成时间：${report.generatedAt}`,
    "",
    "| 指标 | 数值 |",
    "|---|---|",
    `| 会话数 | ${totals.sessions} |`,
    `| 检查次数 | ${totals.checks} |`,
    `| 检查命中 | ${totals.checkHits}（${percent(rates.checkHitRate)}） |`,
    `| 安装移交 | ${totals.installHandoffs} |`,
    `| 健康通过 | ${totals.healthOk} |`,
    `| 健康失败 | ${totals.healthFail} |`,
    `| 健康成功率 | ${percent(rates.healthSuccessRate)} |`,
    `| 下载总量 | ${totals.downloadBytes} 字节 |`,
    `| 平均锁库耗时 | ${lock.averageDurationMs === null ? "<无数据>" : `${lock.averageDurationMs} ms`} |`,
    "",
    "## 失败错误码",
    "",
  ];
  const failures = Object.entries(report.failuresByCode).sort((a, b) => b[1] - a[1]);
  if (failures.length === 0) {
    lines.push("无失败事件。");
  } else {
    lines.push("| 错误码 | 次数 |", "|---|---|");
    for (const [code, count] of failures) lines.push(`| ${code} | ${count} |`);
  }
  lines.push("", "## 事件计数", "", "| 事件 | 次数 |", "|---|---|");
  for (const [event, count] of Object.entries(report.eventCounts).sort((a, b) => b[1] - a[1])) {
    lines.push(`| ${event} | ${count} |`);
  }
  return `${lines.join("\n")}\n`;
}

function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(
      "用法: node scripts/updater/updater_report.mjs [--log-dir <目录>] [--out <json>] [--markdown <md>]",
    );
    return;
  }
  const dirs = args["log-dir"] ? [resolve(args["log-dir"])] : DEFAULT_DIRS;
  const records = readRecords(dirs);
  if (records.length === 0) fail("未找到可解析的更新日志");
  const report = aggregate(records);
  if (args.out) {
    const out = resolve(args.out);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    console.log(`[ OK ] JSON 报告: ${out}`);
  }
  if (args.markdown) {
    const out = resolve(args.markdown);
    mkdirSync(dirname(out), { recursive: true });
    writeFileSync(out, toMarkdown(report), "utf8");
    console.log(`[ OK ] Markdown 报告: ${out}`);
  }
  console.log(
    `[ OK ] 会话 ${report.totals.sessions}，检查命中 ${report.totals.checkHits}，` +
      `安装移交 ${report.totals.installHandoffs}，健康通过 ${report.totals.healthOk}`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main();
}
