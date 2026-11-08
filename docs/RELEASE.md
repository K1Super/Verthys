# 发布流程（RELEASE）

> 版本号规则、发版检查清单、tag 与发布物流程、回滚方案。
>
> Last updated: 2026-10-23 · 维护人：K1Super

当前版本 4.1.7（唯一手改点：仓库根 `VERSION` 文件）。本机更新物料由 `scripts/release/release_update.mjs` 生成；production 默认使用 HTTPS 端点，也可通过 `-AllowInsecureUpdater` 放行 HTTP + IP 自建分发。production 发布要求发布者 Authenticode 证书：构建期把证书 SHA-256 钉扎进 DLL，并对三个可执行产物签名；安装包自身签名仍为可选层。

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

1. 代码冻结：合并窗口关闭，`docs/` 与代码同 PR 同步更新。
2. 发布前置：`powershell -File ci\release_preflight.ps1 -Profile local`；production 追加 `-UpdaterEndpoint https://...`（HTTP + IP 自建时加 `-AllowInsecureUpdater`），并实际探测端点可达性。任一阻断项未解决不得构建。production 还必须注入发布者证书：`VERTHYS_SIGNING_THUMBPRINT` 或 `VERTHYS_SIGNING_PFX` + `VERTHYS_SIGNING_PFX_PASSWORD`；可选 `VERTHYS_PUBLISHER_SHA256` 交叉校验与 `VERTHYS_SIGNING_TIMESTAMP_URL` 时间戳服务。
3. 全量构建：本机验证执行 `build_production.ps1 -Profile local -AllowLocal -Clean -NoPause`；外部分发执行 `-Profile production -UpdaterEndpoint https://...`（HTTP + IP 时加 `-AllowInsecureUpdater`），构建末尾自动调用 `release_update.mjs`。
4. 测试全绿：`ctest --test-dir build -C Release --output-on-failure`；`cargo test`、`npx vitest run`、`npx vue-tsc --noEmit` 全部通过。
5. 更新物料：确认 `build/updater/releases/<release_id>/` 下 `latest.json`、安装包、`.sig`、`release-manifest.json` 与 `channel-pointer.json` 五件齐全，清单版本与 PE `FileVersion` 一致。
6. 回环与回源验证：本机启动 `scripts/updater/updater_server.mjs`，执行 `check_updater_origin.mjs`；需要边缘回源时执行 `check_cdn_edge.mjs`；需要真实升级时按 `updater_e2e_matrix.mjs` 执行。
7. 签名复核：production 必须确认 `verthys.dll`、`verthys-worker.exe`、`Verthys.exe` 三件 Authenticode 状态为 Valid 且签名者证书 SHA-256 与钉扎值一致；构建期功能门禁已覆盖未签名进程返回 `UNAUTHORIZED` 与签名宿主放行。安装包自身未签仅告警，不影响上传。
8. NSIS 包冒烟：在干净机器安装 `src-tauri/target/release/bundle/nsis/*.exe`，按 [DEPLOYMENT.md](DEPLOYMENT.md) 第 5 节做安装后验证。
9. 打 tag：`git tag -a v<version> -m "Release <version>"` 并推送远端（命令须与当次版本号一致）。
10. 更新 CHANGELOG：按 Keep a Changelog（Added/Changed/Fixed/Security）追加版本段，与 tag 对应。

### 2.1 发布者证书（自建 CA，受控分发）

当前发布者证书由项目自建根 CA 签发，仅对安装了根证书的机器有效；公众分发仍需 OV 证书或微软商店。

| 项 | 值 |
|---|---|
| 发布者主题 | `CN=Verthys, O=K1Super, C=CN` |
| 叶证书指纹 | `8891AD5AEA266EE94261D31581E707E3637152EA` |
| 发布者 SHA-256 | `cbb8aac943e90df3e11668fbd507ed15e05c9c9bbe03b240697a450f088d3849` |
| 叶证书有效期 | 2026-11-06 ~ 2028-11-06（到期前 90 天轮换） |
| 根证书 | `CN=Verthys Root CA, O=K1Super, C=CN`，指纹 `75B9904B760B8760ABC1E20E8333DFCD32D0B3A1`，有效期 2026-11-06 ~ 2036-11-06 |
| 私钥备份 | `%USERPROFILE%\.verthys-ca\VerthysRootCA.pfx`、`VerthysCodeSigning.pfx`（加密，离线保存） |

- 构建机信任：根证书必须位于 `Cert:\CurrentUser\Root` 或 `Cert:\LocalMachine\Root`，否则签名复核返回未知/不受信
- 环境持久化：首次签发或证书轮换后执行 `scripts/signing/Set-VerthysBuildSigningEnv.ps1`，把叶证书指纹与时间戳地址写入用户级环境变量，新终端即可直接构建
- 时间戳：设置 `VERTHYS_SIGNING_TIMESTAMP_URL=http://timestamp.digicert.com`，保证叶证书到期后旧安装包仍可验证
- 签发与校验：`scripts/signing/New-VerthysRootCA.ps1`、`New-VerthysCodeSigningCert.ps1`、`Install-VerthysRootTrust.ps1`、`Set-VerthysBuildSigningEnv.ps1`、`Test-VerthysCodeSigningCert.ps1`
- 根私钥不进证书库常驻，只以加密 PFX 离线保存；口令由维护人单独保管
- 换证书会改变 DLL 钉扎值，必须整体重建三件产物
- 安装包自身未做 Authenticode 签名（发布策略允许层），更新签名仍由 Tauri 更新密钥生成

## 3. tag 与发布物流程

```powershell
git tag -a v4.1.7 -m "Release 4.1.7"
git push origin v4.1.7
```

发布物 = `release_update.mjs` 生成的更新物料目录。`.github/workflows/release-materials.yml` 可手动触发，从源码复现 local 物料并上传工件；production 由维护人在受控密钥的发布机执行，HTTPS 或显式放行的 HTTP + IP 端点均可。tag 为本地仓库标签，产出物由维护人手动分发。

## 4. 回滚方案

- 版本回退：`git checkout <上一稳定 tag>` 重新走全量构建与上述检查清单产出旧版安装包。
- 数据兼容声明：数据容器（`.verthys`）的 schema 迁移、旧版本处理、breaking changes 与降级注意事项统一见 [MIGRATION.md](MIGRATION.md)；回滚安装包前先核对目标版本的迁移矩阵，避免退回版本无法读取已被更高版本迁移过的容器。
- 应急拦截：若回滚源于安全缺陷，按 [SECURITY_DESIGN.md](SECURITY_DESIGN.md) 的威胁模型与应急响应流程处置。