# 常见问题排查（TROUBLESHOOTING）

> 按构建/运行/安全与容器/清理卸载分类的症状→原因→排查→解决四列表与诊断命令、日志位置。
>
> Last updated: 2026-09-19 · 维护人：K1Super

本文只收录可从构建脚本与代码注释溯源的已确认问题。涉及安全边界的条目不编造具体错误码，统一以 `core/include/error_codes.h` 的标准化错误码为准。构建矩阵与流程见 [BUILD.md](BUILD.md)，首次搭环境见 [GETTING_STARTED.md](GETTING_STARTED.md)。

## 1. 构建类

| 症状 | 可能原因 | 排查步骤 | 解决方法 |
|---|---|---|---|
| 双击构建脚本窗口一闪而过、无任何输出（`ParseError`） | 脚本未保存为 UTF-8 with BOM，PowerShell 5.1 按 ANSI/GBK 解码中文注释，破坏字符串/括号配对；解析错误先于任何代码执行 | 用十六进制查看器确认文件头不是 `EF BB BF` | 用支持 BOM 的编辑器另存为 UTF-8 with BOM（`build_production.ps1:3-7`） |
| 链接报 `LNK2019`：`vswhom_find_visual_studio_and_windows_sdk` 未解析 | `cl.exe` 不在 PATH，cc crate 编译 vswhom-sys 失败 | `Get-Command cl.exe` 无结果 | dot-source 加载 `scripts/env.load.ps1`（设 CC/CXX=cl.exe，见 `build_dev.ps1:30-60`） |
| `LNK1181`：无法打开输入文件 `windows.0.52.0.lib` | dev profile 增量编译与 raw-dylib 导入库生成竞态 | 清空 `target/` 后复现；缓存失效时发生 | `[profile.dev] incremental=false` + `$env:CARGO_INCREMENTAL=0` + `.cargo/config.toml` 的 `--cfg=windows_raw_dylib`（`build_production.ps1:255-260`；`worker/Cargo.toml:31-37`） |
| cargo 构建被残留锁文件阻塞 | 上次构建的 `.cargo-lock` 未清理 | `Get-ChildItem src-tauri/target -Filter .cargo-lock -Recurse` | 删除 `.cargo-lock`，或依赖脚本自动清理（`build_production.ps1:146-151`、`:516`） |
| `keyboard-types-patched 目录缺失` | `[patch.crates-io]` 本地补丁目录缺失/不完整 | 检查 `verthys-tauri/keyboard-types-patched/{Cargo.toml,src/modifiers.rs}` | 补齐补丁目录（`build_production.ps1:193-207`） |
| `npm install` 触发脚本在 stderr 处理处终止 | `$ErrorActionPreference="Stop"` 将 npm 的 stderr 包装为 ErrorRecord | 查看 `build_err.log` 与终端尾部 | 已内置修复（变量捕获模式，`build_production.ps1:168-190`）；若为网络问题检查 `VERTHYS_GH_MIRROR` |
| CI 与本地构建结果/命令不一致 | CI 用 Ninja 生成器，本地用 VS 生成器；测试 exe 路径不同 | 对照 `.github/workflows/core.yml:34-45` | 本地用 `-G $VERTHYS_VS_GENERATOR -A x64`，CI 用 `-G Ninja`；测试命令按各自路径 |

## 2. 运行类

| 症状 | 可能原因 | 排查步骤 | 解决方法 |
|---|---|---|---|
| 前端 vite 构建报“文件被另一进程占用” | `node`/`esbuild` 残留进程持有 `dist/` 或缓存文件句柄 | `Get-Process node,esbuild` 查看占用进程并核对 PID | `Stop-Process -Id <PID> -Force` 后重试；脚本阶段 0 已自动杀死 `cargo/rustc/verthys-tauri/verthys-worker` 僵尸进程（`build_production.ps1:119-144`） |
| 启动 dev 报端口 1420 已被占用 | 残留 `verthys-tauri` 进程占用 1420 | `Get-NetTCPConnection -LocalPort 1420 -State Listen` 查 `OwningProcess` | `Stop-Process -Id <OwningProcess> -Force`（`build_dev.ps1:88-110` 已自动处理） |
| dev 模式“worker 就绪信号超时” | `src-tauri/target/{debug,release}/` 下旧 worker 副本被优先匹配 | 比对 `verthys-worker/target/release` 与 `src-tauri/target/release` 的 worker 哈希 | 触发 `build_production.ps1 -SkipTauri -NoPause` 重新同步 + 哈希校验（`build_production.ps1:333-338`） |
| dev 模式 cl.exe 仍不在 PATH | 未加载 MSVC 环境或严格模式污染 | `Get-Command cl.exe` 无结果 | 按 `build_dev.ps1:39-60` 加载 `env.load.ps1` 并恢复 EAP/StrictMode |

## 3. 安全与容器类

| 症状 | 可能原因 | 排查步骤 | 解决方法 |
|---|---|---|---|
| 容器无法打开 / 解锁失败 | 认证失败、数据损坏、回滚攻击检测等；**具体错误码以 `core/include/error_codes.h` 为准**（含 `VERTHYS_C_ERR_AUTH`、`VERTHYS_C_ERR_CORRUPT`、`VERTHYS_C_ERR_ROLLBACK` 等），本文不编造错误码 | 从应用侧错误提示取值，对照 `error_codes.h` 与 Rust 侧 `util/ffi.rs` 的错误码映射 | 按错误码定位：认证类走 [SECURITY_DESIGN.md](SECURITY_DESIGN.md)；版本间数据迁移/降级走 [MIGRATION.md](MIGRATION.md) |
| 启动即被完整性/反调试告警拦截 | `.vsec` / `.rhat` 运行时校验、反调试或应急响应触发 | 查看日志中 integrity/runtime_hash/emergency 相关记录 | 属于产品安全设计行为，处理原则见 [SECURITY_DESIGN.md](SECURITY_DESIGN.md)，勿绕过校验 |

## 4. 清理与卸载类

| 症状 | 可能原因 | 排查步骤 | 解决方法 |
|---|---|---|---|
| 构建目录脏、残留旧产物 | `-Clean` 未使用或清理不彻底 | `Get-ChildItem build,build_dev,build_fuzz,verthys-tauri/verthys-worker/target,verthys-tauri/src-tauri/target` | `build_production.ps1 -Clean -NoPause` 或手动 `Remove-Item -Recurse -Force <目录>` |
| 卸载后仍有残留进程 | 应用/worker 未退出 | `Get-Process verthys-tauri,verthys-worker` | `Stop-Process -Name verthys-tauri,verthys-worker -Force`（注意用 PowerShell 原生 cmdlet，勿用 taskkill，见 `build_production.ps1:119-126`） |

## 5. 诊断命令汇总与日志位置

```powershell
# 占用/残留进程
Get-Process node,esbuild,cargo,rustc,verthys-tauri,verthys-worker -ErrorAction SilentlyContinue
# 端口占用
Get-NetTCPConnection -LocalPort 1420 -State Listen -ErrorAction SilentlyContinue
# MSVC 工具可用性
Get-Command cl.exe,cmake -ErrorAction SilentlyContinue
# 测试（带详细输出，仅枚举失败更易定位）
ctest --test-dir build -C Release --output-on-failure -V
# 环境变量
[System.Environment]::GetEnvironmentVariable('VERTHYS_VS_ROOT','User')
```

日志位置：构建错误日志 `verthys-tauri/build_err.log`（脚本阶段 0.6 清理、`build_dev.ps1` 清理后重建）；cargo/前端/tui 详细输出在脚本终端，另见 `.github/workflows/core.yml` 的 fuzz 工件留存策略。