#!/usr/bin/env node
// Tauri 工具链版本门：JS 插件与 Rust crate 必须同 major.minor，
// 且 node_modules 必须与 package-lock.json 完全一致。
//
// Tauri CLI 只会在构建时打印版本不匹配警告，不会阻断；插件侧一旦出现
// 跨 minor 的协议差异，会在运行时表现为 IPC 参数丢失或权限判定不一致。
// 本门把它们提前到安装/构建入口：不通过即退出码 1。
//
// 由 npm predev / prebuild 与 ci/release_preflight.ps1 调用。

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Rust 版本一律以 Cargo.lock 为准：它是实际参与编译的解析结果，
// Cargo.toml 的声明只用于校验是否精确锁定。
const PLUGINS = [
  { rustCrate: 'tauri-plugin-dialog', jsPackage: '@tauri-apps/plugin-dialog' },
  { rustCrate: 'tauri-plugin-fs', jsPackage: '@tauri-apps/plugin-fs' },
  { rustCrate: 'tauri-plugin-process', jsPackage: '@tauri-apps/plugin-process' },
];

const EXACT_VERSION = /^\d+\.\d+\.\d+$/;

function readFile(relativePath) {
  return readFileSync(path.join(projectRoot, relativePath), 'utf8');
}

function readJson(relativePath) {
  return JSON.parse(readFile(relativePath));
}

function tryReadJson(relativePath) {
  try {
    return readJson(relativePath);
  } catch {
    return null;
  }
}

function majorMinor(version) {
  const [major, minor] = version.split('.');
  return `${major}.${minor}`;
}

// Cargo.lock 按 [[package]] 分块，name/version 位于块首。
function readCargoLockVersions() {
  const text = readFile(path.join('src-tauri', 'Cargo.lock'));
  const versions = new Map();
  for (const block of text.split('[[package]]')) {
    const name = block.match(/^\s*name\s*=\s*"([^"]+)"/m);
    const version = block.match(/^\s*version\s*=\s*"([^"]+)"/m);
    if (name && version) {
      versions.set(name[1], version[1]);
    }
  }
  return versions;
}

// 直接依赖必须是精确锁（"=x.y.z"），否则 npm 侧范围会把 Rust 侧甩开。
function readDirectCargoPins() {
  const text = readFile(path.join('src-tauri', 'Cargo.toml'));
  const pins = new Map();
  for (const { rustCrate } of PLUGINS) {
    const match = text.match(new RegExp(`^\\s*${rustCrate}\\s*=\\s*"([^"]+)"\\s*$`, 'm'));
    if (match) {
      pins.set(rustCrate, match[1]);
    }
  }
  return pins;
}

function fail(errors) {
  console.error('\n[Tauri 工具链版本门] 失败');
  for (const error of errors) {
    console.error(`  - ${error}`);
  }
  console.error('\n修复方式：');
  console.error('  cd verthys-tauri && npm ci');
  console.error('  升级插件时必须同时改 Cargo.toml 与 package.json，并重新生成两侧锁文件');
  process.exit(1);
}

const packageJson = readJson('package.json');
const packageLock = readJson('package-lock.json');
const cargoLockVersions = readCargoLockVersions();
const directPins = readDirectCargoPins();
const errors = [];
const rows = [];

for (const { rustCrate, jsPackage } of PLUGINS) {
  const jsSpec = packageJson.dependencies?.[jsPackage];
  const rustVersion = cargoLockVersions.get(rustCrate);
  const installed = tryReadJson(path.join('node_modules', jsPackage, 'package.json'))?.version;
  const locked = packageLock.packages?.[`node_modules/${jsPackage}`]?.version;

  if (!rustVersion) {
    errors.push(`Cargo.lock 缺少 ${rustCrate}：Rust 依赖树不完整`);
    continue;
  }
  if (!jsSpec) {
    errors.push(`package.json 缺少依赖 ${jsPackage}`);
    continue;
  }
  if (!EXACT_VERSION.test(jsSpec)) {
    errors.push(`${jsPackage} 必须使用精确版本，当前为 "${jsSpec}"`);
  }
  const lockSpec = packageLock.packages?.['']?.dependencies?.[jsPackage];
  if (lockSpec !== jsSpec) {
    errors.push(
      `package-lock.json 根声明 "${lockSpec ?? '缺失'}" 与 package.json "${jsSpec}" 不一致：请重新生成锁文件`,
    );
  }
  if (directPins.has(rustCrate)) {
    const pin = directPins.get(rustCrate);
    if (!pin.startsWith('=')) {
      errors.push(`${rustCrate} 在 Cargo.toml 必须精确锁定（=版本），当前为 "${pin}"`);
    } else if (pin.slice(1) !== rustVersion) {
      errors.push(`${rustCrate} 的 Cargo.toml 锁定与 Cargo.lock 不一致：${pin} vs ${rustVersion}`);
    }
  }
  if (!installed) {
    errors.push(`node_modules 缺少 ${jsPackage}：请先执行 npm ci`);
    continue;
  }
  if (!locked) {
    errors.push(`package-lock.json 缺少 ${jsPackage} 记录：请重新生成锁文件`);
  } else if (installed !== locked) {
    errors.push(
      `${jsPackage} 实装 ${installed} 与锁文件 ${locked} 不一致：node_modules 已漂移，请执行 npm ci`,
    );
  }
  if (majorMinor(installed) !== majorMinor(rustVersion)) {
    errors.push(
      `${jsPackage} ${installed} 与 ${rustCrate} ${rustVersion} 的 major.minor 不一致`,
    );
  }
  rows.push(
    `${jsPackage.padEnd(36)} rust=${rustVersion.padEnd(8)} js=${String(installed).padEnd(8)} lock=${locked ?? '缺失'}`,
  );
}

if (errors.length > 0) {
  fail(errors);
}

console.log('[Tauri 工具链版本门] 通过');
for (const row of rows) {
  console.log(`  ${row}`);
}
