/*
 * 清单生成脚本的纯函数回归。
 *
 * 只验证版本归一化、发布标识时间格式与核心版本解析；文件级哈希与签名由实际发布流程覆盖。
 */
import test from "node:test";
import assert from "node:assert/strict";
import {
  buildArtifactUrl,
  buildReleaseId,
  compatibilityRangeError,
  formatAbiVersion,
  isReleaseId,
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

test("发布标识由安装包 SHA256 压缩为 13 位融合哈希", () => {
  const sha = "05ad359255fe4aa703ce628ee56cac4b83e7f03c6ccfe5e96310ba39abe713b7";
  assert.equal(buildReleaseId(sha), "0ppkb4jnzs5ae");
  assert.match(buildReleaseId(sha), /^[0-9a-hjkmnp-tv-z]{13}$/);
  assert.equal(buildReleaseId("0".repeat(64)), "0000000000000");
  assert.throws(() => buildReleaseId(sha.toUpperCase()));
});

test("发布标识兼容融合哈希与旧日期格式", () => {
  assert.equal(isReleaseId("0ppkb4jnzs5ae"), true);
  assert.equal(isReleaseId("20261023-164858-4.1.7-4e64707c"), true);
  assert.equal(isReleaseId("0ppkb4jnzs5ai"), false);
  assert.equal(isReleaseId("0ppkb4jnzs5aO"), false);
  assert.equal(isReleaseId("short"), false);
  assert.equal(isReleaseId(""), false);
});

test("物料地址按 release 级不可变路径派生", () => {
  assert.equal(
    buildArtifactUrl(
      "http://120.79.122.69/releases/",
      "20261023-120000-4.1.7-a1b2c3d4",
      "Verthys_4.1.7_x64-setup.exe",
    ),
    "http://120.79.122.69/releases/20261023-120000-4.1.7-a1b2c3d4/artifacts/Verthys_4.1.7_x64-setup.exe",
  );
  assert.equal(
    buildArtifactUrl("https://updates.example.com/releases", "r1", "a b.exe"),
    "https://updates.example.com/releases/r1/artifacts/a%20b.exe",
  );
  assert.throws(() => buildArtifactUrl("ftp://host/releases", "r1", "x.exe"));
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
