# 发布流程（RELEASE）

> 版本号规则、发版检查清单、tag 与发布物流程、回滚方案。
>
> Last updated: 2026-09-19 · 维护人：K1Super

当前版本 3.3.0（唯一手改点：仓库根 `VERSION` 文件）。发布为本地 Git tag + 手动产物分发，无远程发布渠道；本文档定义一致、可验收的发版流程。

## 1. 版本号规则

遵循语义化版本 SemVer：`MAJOR.MINOR.PATCH`。版本号单一权威源为仓库根 `VERSION` 文件（单行 semver），其余载体全部自动派生，禁止手工改载体：

| 载体 | 更新方式 |
|---|---|
| `CMakeLists.txt` | 构建期读取 `VERSION` 并校验 semver（缺失/非法即配置失败） |
| `verthys-tauri/src-tauri/Cargo.toml`、`verthys-tauri/verthys-worker/Cargo.toml` | `ci\sync_version.ps1` 同步 |
| `verthys-tauri/package.json`、`verthys-tauri/package-lock.json` | `ci\sync_version.ps1` 同步 |
| `verthys-tauri/src/app/config.ts` 回退值 | `ci\sync_version.ps1` 同步 |
| `verthys-tauri/src-tauri/tauri.conf.json` | 不承载版本：Tauri 工具链回退取 src-tauri crate 版本 |
| 前端运行期 `import.meta.env.VITE_APP_VERSION` | vite 构建期读取 `VERSION` 注入 |

升版命令：编辑根 `VERSION` → `powershell -ExecutionPolicy Bypass -File ci\sync_version.ps1` → 审阅 `git diff` 后提交。CI 门禁（`run_ci.ps1` 与两个 GitHub 工作流）执行 `-CheckOnly` 漂移校验，任何载体与 `VERSION` 不一致即红。

## 2. 发版检查清单（逐项可验收）

1. 代码冻结：合并窗口关闭，`docs/` 与代码同 PR 同步更新（见 [DOCUMENTATION_CHECKLIST.md](DOCUMENTATION_CHECKLIST.md) 第 4 节）。
2. 全量构建：`powershell -ExecutionPolicy Bypass -File build_production.ps1 -Clean -NoPause` 全绿（`build_production.ps1:22`）。
3. 测试全绿：`ctest --test-dir build -C Release --output-on-failure`，`verthys_tests` 聚合测试内含 296 个用例全部通过（实际测试数见 [TESTING.md](TESTING.md)）；必要时运行 fuzz 冒烟门。
4. 前端类型检查：`npx vue-tsc --noEmit` 通过（打包脚本阶段 4 已含，`build_production.ps1:398`）。
5. Rust 检查：`cargo check` 通过（`build_production.ps1:417`）；`npm run tauri build` 成功产出 NSIS 包。
6. 产物哈希校验：阶段 3.3 的 `Get-FileSha256` 副本比对无哈希漂移（`build_production.ps1:365-391`）。
7. NSIS 包冒烟：在干净机器安装 `src-tauri/target/release/bundle/nsis/*.exe`，按 [DEPLOYMENT.md](DEPLOYMENT.md) 第 5 节做安装后验证。
8. 打 tag：`git tag -a v3.3.x -m "Release 3.3.x"` 并 `git push origin v3.3.x`（命令须与当次版本号一致）。
9. 更新 CHANGELOG：按 Keep a Changelog（Added/Changed/Fixed/Security）追加版本段，与 tag 对应。

## 3. tag 与发布物流程

```powershell
git tag -a v3.3.0 -m "Release 3.3.0"
git push origin v3.3.0
```

发布物 = 手动上传的 NSIS 安装包（`*.exe`）。当前 `.github/workflows/` 仅有 `core.yml`（core 构建与测试 + fuzz），无 release 发布工作流，故发布渠道待定；tag 为本地仓库标签，产出物由维护人手动分发。

## 4. 回滚方案

- 版本回退：`git checkout <上一稳定 tag>` 重新走全量构建与上述检查清单产出旧版安装包。
- 数据兼容声明：数据容器（`.verthys`）的 schema 迁移、旧版本处理、breaking changes 与降级注意事项统一见 [MIGRATION.md](MIGRATION.md)；回滚安装包前先核对目标版本的迁移矩阵，避免退回版本无法读取已被更高版本迁移过的容器。
- 应急拦截：若回滚源于安全缺陷，走 [SECURITY.md](../SECURITY.md) 的漏洞上报与升级流程（该文件属根目录安全策略）。