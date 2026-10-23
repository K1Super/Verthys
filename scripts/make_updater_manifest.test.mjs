/*
 * 清单生成脚本的纯函数回归。
 *
 * 只验证版本归一化、发布标识时间格式与核心版本解析；文件级哈希与签名由实际发布流程覆盖。
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  compatibilityRangeError,
  formatAbiVersion,
  formatReleaseStamp,
  normalizeFileVersion,
  parseDefineU32,
  readCoreVersions,
} from "./make_updater_manifest.mjs";

test("文件版本归一化为三段", () => {
  assert.equal(normalizeFileVersion("4.1.3.0"), "4.1.3");
  assert.equal(normalizeFileVersion("4.1.3"), "4.1.3");
});

test("非法文件版本返回空", () => {
  assert.equal(normalizeFileVersion("4.1"), null);
  assert.equal(normalizeFileVersion(""), null);
});

test("发布标识时间使用 UTC 紧凑格式", () => {
  assert.equal(formatReleaseStamp(new Date("2026-10-22T09:00:00Z")), "20261022-090000");
});

test("核心版本宏解析支持十六进制与十进制后缀", () => {
  assert.equal(
    parseDefineU32("#define VERTHYS_API_VERSION 0x000Eu", "VERTHYS_API_VERSION"),
    0x000e,
  );
  assert.equal(
    parseDefineU32("#define VERTHYS_V3_VERSION                3u", "VERTHYS_V3_VERSION"),
    3,
  );
  assert.equal(parseDefineU32("#define OTHER 1", "VERTHYS_V3_VERSION"), null);
});

test("核心版本可从仓库头文件读取", () => {
  const versions = readCoreVersions();
  assert.ok(Number.isInteger(versions.api) && versions.api > 0);
  assert.ok(Number.isInteger(versions.container) && versions.container > 0);
});

test("ABI 文本固定为四位十六进制", () => {
  assert.equal(formatAbiVersion(0x000b), "0x000B");
  assert.equal(formatAbiVersion(0x000e), "0x000E");
});

test("兼容区间必须覆盖当前核心", () => {
  const core = { api: 0x000e, container: 3 };
  assert.equal(compatibilityRangeError("0x000E", "0x000E", 3, 3, core), null);
  assert.equal(compatibilityRangeError("0x000B", "0x000E", 3, 3, core), null);
  assert.equal(
    compatibilityRangeError("0x000B", "0x000B", 3, 3, core),
    "兼容 ABI 区间不包含当前核心 ABI",
  );
  assert.equal(
    compatibilityRangeError("0x000E", "0x000E", 2, 2, core),
    "容器兼容区间不包含当前容器版本",
  );
});
