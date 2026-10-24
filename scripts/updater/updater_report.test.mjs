/*
 * 更新发布报告聚合契约。
 *
 * 健康结论在新进程产生，报告必须按事件计数聚合，不能把安装会话与健康会话
 * 强行拼接成一次成功率。
 */
import assert from "node:assert/strict";
import test from "node:test";
import { aggregate, toMarkdown } from "./updater_report.mjs";

const records = [
  { event: "check_sent", sessionId: "s1", severity: "info", detail: {} },
  {
    event: "check_hit",
    sessionId: "s1",
    severity: "info",
    detail: { toVersion: "4.1.6" },
  },
  { event: "download_success", sessionId: "s1", severity: "info", detail: { bytes: 1000 } },
  { event: "lock_ok", sessionId: "s1", severity: "info", detail: { durationMs: 12 } },
  { event: "install_handoff", sessionId: "s1", severity: "info", detail: {} },
  { event: "health_ok", sessionId: "s2", severity: "info", detail: {} },
  {
    event: "manifest_invalid",
    sessionId: "s3",
    severity: "error",
    code: "E_UPDATER_INSTALL_REVOKED",
    detail: {},
  },
];

test("聚合检查、安装、健康与失败错误码", () => {
  const report = aggregate(records);

  assert.equal(report.totals.sessions, 3);
  assert.equal(report.totals.checks, 1);
  assert.equal(report.totals.checkHits, 1);
  assert.equal(report.totals.installHandoffs, 1);
  assert.equal(report.totals.healthOk, 1);
  assert.equal(report.totals.healthFail, 0);
  assert.equal(report.totals.downloadBytes, 1000);
  assert.equal(report.rates.checkHitRate, 1);
  assert.equal(report.rates.healthSuccessRate, 1);
  assert.equal(report.lock.averageDurationMs, 12);
  assert.equal(report.failuresByCode.E_UPDATER_INSTALL_REVOKED, 1);
  assert.equal(report.toVersions["4.1.6"], 1);
});

test("Markdown 报告使用与 JSON 一致的字段", () => {
  const markdown = toMarkdown(aggregate(records));
  assert.match(markdown, /\| 检查次数 \| 1 \|/);
  assert.match(markdown, /\| 健康成功率 \| 100\.0% \|/);
  assert.doesNotMatch(markdown, /undefined/);
});

test("没有健康结论时成功率留空而不是伪造 0", () => {
  const report = aggregate([{ event: "check_sent", sessionId: "s1", severity: "info" }]);
  assert.equal(report.rates.healthSuccessRate, null);
  assert.equal(report.totals.sessions, 1);
});
