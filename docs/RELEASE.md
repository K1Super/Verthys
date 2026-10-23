# 发布流程（RELEASE）

> 版本号规则、发版检查清单、tag 与发布物流程、回滚方案。
>
> Last updated: 2026-10-23 · 维护人：K1Super

当前版本 4.1.7（唯一手改点：仓库根 `VERSION` 文件）。本机更新物料由 `scripts/release_update.mjs` 生成；production 仍需真实 HTTPS 端点与 Authenticode 证书，当前无远程发布渠道。

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
2. 发布前置：`powershell -File ci\release_preflight.ps1 -Profile local`；production 追加 `-UpdaterEndpoint https://...` 与 `-AuthenticodeThumbprint <指纹>`，并实际探测端点 HTTPS 可达性。任一阻断项未解决不得构建。
3. 全量构建：本机验证执行 `build_production.ps1 -Profile local -AllowLocal -Clean -NoPause`；外部分发执行 `-Profile production -UpdaterEndpoint https://...`，构建末尾自动调用 `release_update.mjs`。
4. 测试全绿：`ctest --test-dir build -C Release --output-on-failure`；`cargo test`、`npx vitest run`、`npx vue-tsc --noEmit` 全部通过。
5. 更新物料：确认 `build/updater/releases/<release_id>/` 下 `latest.json`、安装包、`.sig`、`release-manifest.json` 与 `channel-pointer.json` 五件齐全，清单版本与 PE `FileVersion` 一致。
6. 回环与回源验证：本机启动 `scripts/updater_server.mjs`，执行 `check_updater_origin.mjs`；需要边缘回源时执行 `check_cdn_edge.mjs`；需要真实升级时按 `updater_e2e_matrix.mjs` 执行。
7. 签名复核：production 安装包在构建后自动复核 Authenticode 系统信任链；未通过不得上传。
8. NSIS 包冒烟：在干净机器安装 `src-tauri/target/release/bundle/nsis/*.exe`，按 [DEPLOYMENT.md](DEPLOYMENT.md) 第 5 节做安装后验证。
9. 打 tag：`git tag -a v<version> -m "Release <version>"` 并推送远端（命令须与当次版本号一致）。
10. 更新 CHANGELOG：按 Keep a Changelog（Added/Changed/Fixed/Security）追加版本段，与 tag 对应。

## 3. tag 与发布物流程

```powershell
git tag -a v4.1.7 -m "Release 4.1.7"
git push origin v4.1.7
```

发布物 = `release_update.mjs` 生成的更新物料目录。`.github/workflows/release-materials.yml` 可手动触发，从源码复现 local 物料并上传工件；production 仍由维护人在具备真实证书与受控密钥的发布机执行。tag 为本地仓库标签，产出物由维护人手动分发。

## 4. 回滚方案

- 版本回退：`git checkout <上一稳定 tag>` 重新走全量构建与上述检查清单产出旧版安装包。
- 数据兼容声明：数据容器（`.verthys`）的 schema 迁移、旧版本处理、breaking changes 与降级注意事项统一见 [MIGRATION.md](MIGRATION.md)；回滚安装包前先核对目标版本的迁移矩阵，避免退回版本无法读取已被更高版本迁移过的容器。
- 应急拦截：若回滚源于安全缺陷，走 [SECURITY.md](../SECURITY.md) 的漏洞上报与升级流程（该文件属根目录安全策略）。