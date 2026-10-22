# Verthys 更新服务器部署方案（SERVER DEPLOYMENT PLAN）

> 文档编号：VUP-002
> 状态：**待启用执行方案**（Phase S；本机阶段不执行）
> 适用对象：Windows x64 客户端；Linux 服务器 / 对象存储 / CDN
> 前置条件：[UPDATER_MASTER_PLAN.md](UPDATER_MASTER_PLAN.md) Phase L0 退出，且客户端 readiness C01 ~ C12 完成
> 关联文档：[UPDATER_MASTER_PLAN.md](UPDATER_MASTER_PLAN.md) §8、[../SECURITY_DESIGN.md](../SECURITY_DESIGN.md)、[../DEPLOYMENT.md](../DEPLOYMENT.md)、[../RELEASE.md](../RELEASE.md)
>
> Last updated: 2026-10-22 · 维护人：K1Super

---

## 0. 执行摘要

### 0.1 目标

把当前本机回环更新链路升级为**可对外分发的 HTTPS 更新服务**，满足：

1. 客户端从稳定 HTTPS 端点获取签名清单与安装包。
2. 清单、安装包、Authenticode 三层校验；任何一层失败即拒绝安装。
3. stable / beta / internal 三渠道隔离；灰度按比例放量；可暂停、可撤回、可强制升级。
4. 发布物料不可变、可追溯、可回滚；签名私钥不在 Web 服务器。
5. 客户端事件可聚合，能计算成功率、验签失败、回滚率；阈值告警可触发暂停。
6. 单机可运行，后续可平滑扩展到对象存储 + CDN + WAF。

### 0.2 架构选择

**Static-first，不做动态更新 API 依赖。**

- 清单由 CI / 构建机生成并签名，作为静态 JSON 托管。
- 渠道通过独立路径 + 独立清单隔离，不在服务端做版本决策。
- 灰度、暂停、撤回通过清单字段（`rollout` / `paused` / `revoked_release_ids`）由客户端执行。
- 控制面（可选）只负责生成清单与审计，不在请求路径上。
- 这样做的代价是“发布即静态文件”，收益是攻击面小、缓存友好、可用性高、可直接回滚。

### 0.3 三种部署形态

| 形态 | 组成 | 适用 | 优点 | 限制 |
|---|---|---|---|---|
| M0 单机 | 1 台 Linux VPS + Nginx + TLS + 静态目录 | 内部 / 试点 / 小规模稳定 | 成本低、可快速上线、运维简单 | 单点故障；带宽有限；无边缘缓存 |
| M1 对象存储 + CDN | S3 / R2 / OSS + CDN + WAF + 静态清单 | 外部分发 / 规模化 | 高可用、弹性带宽、边缘缓存、DDoS 防护 | 配置复杂；成本随流量 |
| M2 控制面（可选） | 发布服务 + 数据库 + 审计 + 清单生成 | 多产品 / 多渠道 / 审批 | 发布流程产品化、审计完整 | 增加攻击面与运维；非必需 |

**推荐路径**：先用 M0 完成 internal / beta 验证；stable 对外开放前升级到 M1（或 M0 + CDN 代理 + 事件服务）；M2 仅在发布频率和团队规模需要时引入。M0 / M1 / M2 是部署形态，不是发布阶段；发布阶段（S0 / S1）与灰度门见 §7.2。

### 0.4 五条硬规则

1. **Web 服务器不持有签名私钥**：清单签名、安装包签名、Authenticode 都在构建机 / HSM 完成；服务器只托管已签名文件。
2. **物料不可变**：`/releases/<release_id>/...` 永不覆盖；新版本写新路径；清单指针原子切换。
3. **stable 灰度前必须有遥测**：没有事件聚合，不允许 1% 以上放量；否则无法判断成功率与回滚率。
4. **清单单文件签名**：签名内嵌在 `latest.json`，避免清单与 `.sig` 配对窗口；CDN 缓存只缓存不可变物料。
5. **回滚是发布动作**：回滚 = 把渠道指针指回上一份已签名清单；不是删除新版本，也不是改客户端。

---

## 1. 目标与非目标

### 1.1 目标

| 目标 | 验收口径 |
|---|---|
| 可用性 | stable 清单月可用性 ≥ 99.9%；P95 响应 < 200 ms |
| 完整性 | 清单签名、安装包签名、SHA256、PE 版本、Authenticode 全部可验证 |
| 可回滚 | 任意发布可在 5 分钟内通过指针切回上一版本 |
| 可灰度 | 1% → 10% → 50% → 100% 分阶段；阶段门可机器判定 |
| 可暂停 | `paused=true` 后新检查不再返回更新；已下载未安装的会话在安装前复查 |
| 可审计 | 每次发布有 release manifest、操作人、时间、哈希、审批记录 |
| 可观测 | 版本分布、成功率、失败码 TOP、回滚率、渠道分布可查询 |
| 安全 | TLS 1.2+、HSTS、WAF / 限流、最小权限、无私钥落地 |

### 1.2 非目标

- 不做用户账号体系、设备注册、许可证管理。
- 不采集个人信息、容器内容、记录标题、密钥、完整设备指纹。
- 不做 macOS / Linux 分发；当前仅 Windows x64 / NSIS。
- 不做 P2P / 局域网分发（后续企业阶段可加内网镜像）。
- 不做动态“检查更新 API”返回个性化结果；灰度由客户端 bucket 计算。
- 不把 Web 服务器做成构建机；构建与签名分离。

---

## 2. 前置条件与准入

### 2.1 客户端 readiness（必须全部满足）

| # | 能力 | 验收 |
|---|---|---|
| C01 | `production` profile，HTTPS 端点，无回环 / 明文许可 | 配置门 G2 通过 |
| C02 | 清单签名验证 + 可信 key 集 | 篡改清单被拒；旧 / 新 key 均可验 |
| C03 | 安装包签名 + SHA256 + size + PE FileVersion | 负向用例全拒 |
| C04 | Authenticode 验证（`WinVerifyTrust`） | 未签名 / 错证书包被拒 |
| C05 | 渠道选择 + `rollout` bucket | 稳定 bucket；比例边界正确 |
| C06 | `paused` / `revoked_release_ids` / `force_below` | 行为符合 §8 |
| C07 | 安装前在线复查清单 | 暂停 / 撤回后不再安装 |
| C08 | `pending.json` + 健康自检 | 正向 / 失败路径均可复现 |
| C09 | R1 修复入口 / LKG | 健康失败后可修复 |
| C10 | 事件上报（可关闭）+ 本地日志 | 字段白名单；可聚合 |
| C11 | 代理 / 超时 / 重试 / Range 续传 | 断网 / 大文件场景通过 |
| C12 | beta / internal 鉴权头（DPAPI 存储） | 无明文令牌落盘 |

### 2.2 构建与签名 readiness

| 项 | 要求 |
|---|---|
| 构建 profile | `production`；端点 HTTPS；无 `dangerousInsecureTransportProtocol` |
| 安装包签名 | minisign 私钥在受控构建机 / HSM；构建缺失即失败 |
| 清单签名 | 独立密钥；签名脚本可复现；公钥内置客户端 |
| Authenticode | EV / OV 证书或云签名服务；时间戳服务可用 |
| 物料账本 | release manifest、SBOM、安装包 / `.sig` / DLL / worker 哈希 |
| 可复现 | 同 tag 可重建物料清单；至少哈希可追溯 |

### 2.3 组织与运维 readiness

| 项 | 要求 |
|---|---|
| 域名 | 已注册、可解析、可签发证书；建议独立子域 |
| 值班 | 发布窗口有人值守；告警有接收人 |
| 审批 | 发布 / 回滚 / 密钥操作至少双人复核 |
| 回滚演练 | 上线前完成一次指针回滚 + 客户端验证 |
| 密钥预案 | 私钥泄露、证书过期、清单密钥轮换有书面流程 |
| 法务 / 隐私 | 遥测字段、保留期、可关闭；无 PII |

### 2.4 绝对准入条件

以下任意一项不满足，**不得把 stable 对外开放**：

1. 客户端不能验证清单签名。
2. 客户端不能验证 PE 版本。
3. 客户端没有 marker / 健康自检 / R1 修复。
4. 没有事件聚合与告警。
5. 没有可回滚的历史版本与指针切换演练。
6. 构建机私钥 / 证书保管未成文。

---

## 3. 架构

### 3.1 逻辑架构

```text
┌────────────────────────────────────────────────────────────────────┐
│ 构建 / 签名面（受控 Windows 构建机或 CI）                             │
│  build_production.ps1 -Profile production                           │
│  → Authenticode（DLL / worker / 主程序 / NSIS）                      │
│  → updater minisign（安装包）                                        │
│  → Manifest v2（sha256 / size / file_version / compatibility）       │
│  → 清单签名（JCS + minisign）                                        │
│  → release-manifest.json + SBOM                                     │
└───────────────────────────────┬────────────────────────────────────┘
                                │ scp / rsync / CI artifact upload
┌───────────────────────────────▼────────────────────────────────────┐
│ 分发面（M0：Nginx；M1：对象存储 + CDN + WAF）                         │
│  /releases/<release_id>/artifacts/*        immutable                 │
│  /stable/latest.json                       signed manifest           │
│  /beta/latest.json                         signed manifest + auth    │
│  /internal/latest.json                     signed manifest + auth    │
└───────────────────────────────┬────────────────────────────────────┘
                                │ HTTPS（TLS 1.2+）
┌───────────────────────────────▼────────────────────────────────────┐
│ 客户端（Verthys Rust updater_service）                               │
│  check → verify manifest → prepare（sig / hash / PE / Auth）         │
│  → precheck → lock → install → pending → health → confirmed          │
└───────────────────────────────┬────────────────────────────────────┘
                                │ 脱敏事件（可选、可关闭）
┌───────────────────────────────▼────────────────────────────────────┐
│ 观测面（M0：访问日志 + 客户端本地日志；M1：事件聚合 + 大盘 + 告警）     │
└────────────────────────────────────────────────────────────────────┘
```

### 3.2 信任边界

| 边界 | 信任内容 | 验证方式 |
|---|---|---|
| 客户端 ↔ 分发 | TLS 证书、HTTP 响应 | 系统信任链 + HSTS；证书透明监控 |
| 客户端 ↔ 清单 | 清单 JSON | 内置清单公钥 + JCS 签名 |
| 客户端 ↔ 安装包 | 安装包字节 | minisign + SHA256 + PE 版本 |
| 客户端 ↔ OS | 安装包可执行性 | Authenticode + SmartScreen |
| 构建机 ↔ 服务器 | 上传物料 | SSH key / CI OIDC；上传后哈希复核 |
| 运维 ↔ 控制面 | 发布 / 回滚 | 双人复核 + 审计日志 |

**服务器不在信任链的“签名”位置**：它只是传输者。即使服务器被攻破，攻击者没有私钥也无法伪造清单 / 安装包；但可以拒绝服务或回放旧清单（被版本 / PE / `revoked_release_ids` 阻断）。这是 static-first 的核心安全收益。

### 3.3 部署形态选择

| 维度 | M0 单机 | M1 对象存储 + CDN |
|---|---|---|
| 可用性 | 单点；靠快照 / 备份恢复 | 多副本 / 多边缘；高可用 |
| 带宽 | VPS 带宽上限 | 弹性；适合大文件 |
| 成本 | 低 | 随流量 |
| 运维 | 简单 | 中等 |
| 安全 | Nginx + 防火墙 + fail2ban | + WAF / DDoS / 访问策略 |
| 适用 | internal / beta / 小规模 stable | 外部分发 / 规模化 |

### 3.4 域名与路径

建议使用独立子域，避免与主站共享 Cookie / CSP / 证书：

| 渠道 | URL | 认证 |
|---|---|---|
| stable | `https://updates.verthys.example/stable/latest.json` | 匿名 |
| beta | `https://updates.verthys.example/beta/latest.json` | Bearer / Basic / Access |
| internal | `https://updates.verthys.example/internal/latest.json` | VPN / Access / IP allowlist |

> `updates.verthys.example` 为占位域名，实际部署时替换为已注册域名；`.example` 不会与真实域名冲突。

路径布局：

```text
/srv/verthys/updates/
├── releases/
│   └── 20261022-090000-4.1.4-a1b2c3d4/
│       ├── artifacts/
│       │   ├── Verthys_4.1.4_x64-setup.exe
│       │   ├── Verthys_4.1.4_x64-setup.exe.sig
│       │   └── sbom.cdx.json
│       ├── release-manifest.json
│       └── checksums.txt
├── channels/
│   ├── stable/
│   │   ├── 20261022T090000Z-20261022-090000-4.1.4-a1b2c3d4/
│   │   │   └── latest.json
│   │   └── 20261023T120000Z-20261022-090000-4.1.4-a1b2c3d4/   # 暂停 / 调灰度后的新控制版本
│   ├── beta/
│   │   └── <manifest_revision>/latest.json
│   └── internal/
│       └── <manifest_revision>/latest.json
├── stable -> channels/stable/<manifest_revision>
├── beta -> channels/beta/<manifest_revision>
├── internal -> channels/internal/<manifest_revision>
└── archive/
```

- **物料不可变**：`releases/<release_id>/` 一旦发布不修改；安装包、签名、SBOM、release manifest 只读。
- **清单是控制面**：每个渠道的每个 `manifest_revision` 目录也是一份不可变控制版本；暂停 / 调灰度 / 回滚都生成新的 `manifest_revision`，不修改旧清单。
- **渠道切换**：只原子替换渠道符号链接；`stable/latest.json` 与 `release_id` 的物料通过清单 URL 解耦。
- **清单内嵌签名**：渠道目录只需一个 `latest.json`；无需 `.sig` 配对文件。
- `manifest_revision` 格式：`YYYYMMDDTHHMMSSZ-<release_id>`；同一 `release_id` 可以有多个控制版本。

### 3.5 缓存策略

| 路径 | Cache-Control | CDN | 说明 |
|---|---|---|---|
| `/{channel}/latest.json` | `no-store, max-age=0` | 绕过缓存 / 发布后 purge | 必须实时；客户端每次检查拿最新 |
| `/releases/*/artifacts/*.exe` | `public, max-age=31536000, immutable` | 缓存 | 路径含 release_id，内容不变 |
| `/releases/*/artifacts/*.sig` | `public, max-age=31536000, immutable` | 缓存 | 同上 |
| `/releases/*/sbom.cdx.json` | `public, max-age=86400` | 可选 | 审计用 |
| `/releases/*/release-manifest.json` | `public, max-age=86400` | 可选 | 审计用 |

规则：

1. 安装包路径必须含 `release_id`；禁止覆盖同版本文件。
2. 清单不缓存；如果 CDN 必须缓存，TTL ≤ 30 s 且发布后 purge。
3. 支持 `Range` / `Accept-Ranges: bytes`；客户端 P1 断点续传依赖。
4. 支持 `ETag`；客户端可用于条件请求，但不得用于安全判定。
5. 禁止目录列表；所有未知路径 404。
6. 只允许 `GET` / `HEAD`；其他方法 405。

---

## 4. 域名、TLS 与安全头

### 4.1 DNS

| 记录 | 值 | 说明 |
|---|---|---|
| `A updates.verthys.example` | M0 VPS IPv4 | 必须 |
| `AAAA` | 如有 IPv6 | 可选 |
| `CAA` | `letsencrypt.org` / 证书 CA | 防止误签发 |
| `DNSSEC` | 启用 | 防 DNS 劫持 |

### 4.2 证书

- M0：Let's Encrypt（certbot）或商业 DV 证书；自动续期。
- M1：CDN 托管证书 / ACM；源站证书可选。
- 要求：TLS 1.2+（优先 1.3）；OCSP stapling；HSTS（先 `max-age=86400`，稳定后 1 年 + `includeSubDomains`，确认后再考虑 preload）。
- 监控：到期前 30 / 14 / 7 天告警；证书透明日志异常告警。
- 禁止：自签证书、过期证书、弱 cipher、TLS 1.0/1.1。

### 4.3 安全头

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
Referrer-Policy: no-referrer
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
Permissions-Policy: interest-cohort=()
```

- 不设置 `Access-Control-Allow-Origin`；更新客户端是 Rust 侧请求，不需要 CORS。
- 不返回 `Server` 版本号（`server_tokens off`）。
- 不设置 `Set-Cookie`。

---

## 5. M0 单机基线（Ubuntu 24.04 LTS）

### 5.1 主机规格

| 项 | 建议 |
|---|---|
| CPU | 2 vCPU |
| 内存 | 4 GB |
| 磁盘 | 100 GB SSD（安装包 + 历史版本 + 日志） |
| 带宽 | 按下载量估算；5 MB × 设备数 × 发布次数 |
| 系统 | Ubuntu 24.04 LTS x86_64 |
| 位置 | 目标用户就近区域；备案 / 合规按实际 |

### 5.2 系统加固

```bash
# 以 root 执行一次
adduser --system --group --home /srv/verthys --shell /usr/sbin/nologin verthys
apt update && apt upgrade -y
apt install -y nginx certbot python3-certbot-nginx ufw fail2ban unattended-upgrades curl jq rsync
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw enable

# SSH：仅密钥、禁止 root 密码登录（按实际 sshd_config 调整）
# PermitRootLogin no
# PasswordAuthentication no
# PubkeyAuthentication yes

systemctl enable --now nginx
systemctl enable --now fail2ban
```

要求：

- 不用 root 运行 Nginx worker；Nginx 默认 `www-data`。
- 发布用户 `verthys` 只对 `/srv/verthys/updates` 有写权限；Nginx 只读。
- 开启 `unattended-upgrades`；内核 / OpenSSL 安全更新及时重启。
- 时间同步：`systemd-timesyncd` / chrony；TLS 与日志依赖准确时间。
- 关闭未使用端口；云安全组只放行 22 / 80 / 443。

### 5.3 目录与权限

```bash
install -d -m 0750 -o verthys -g verthys /srv/verthys
install -d -m 0755 -o verthys -g verthys /srv/verthys/updates
install -d -m 0755 -o verthys -g verthys /srv/verthys/updates/releases
install -d -m 0755 -o verthys -g verthys /srv/verthys/updates/archive
install -d -m 0700 -o verthys -g verthys /srv/verthys/secrets
```

- `updates` 目录 0755，文件 0644；Nginx 可读。
- `secrets` 0700，仅发布用户；M0 只放 beta / internal 的 htpasswd，不放签名私钥。
- 不在服务器生成密钥；签名私钥留在构建机 / HSM。

### 5.4 Nginx 配置

`/etc/nginx/snippets/verthys-security-headers.conf`（**必须在每个 `location` 重复 include**，否则 Nginx 的 `add_header` 继承会被当前层覆盖）：

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options nosniff always;
add_header Referrer-Policy no-referrer always;
add_header Content-Security-Policy "default-src 'none'; frame-ancestors 'none'" always;
```

`/etc/nginx/conf.d/verthys-updates.conf`：

```nginx
limit_req_zone $binary_remote_addr zone=manifest:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=artifact:10m rate=300r/m;

server {
    listen 80;
    server_name updates.verthys.example;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name updates.verthys.example;

    root /srv/verthys/updates;
    server_tokens off;
    autoindex off;
    etag on;
    sendfile on;
    tcp_nopush on;

    ssl_certificate     /etc/letsencrypt/live/updates.verthys.example/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/updates.verthys.example/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 1.1.1.1 8.8.8.8 valid=300s;
    resolver_timeout 5s;

    include /etc/nginx/snippets/verthys-security-headers.conf;

    # 只允许 GET / HEAD
    if ($request_method !~ ^(GET|HEAD)$) { return 405; }

    # 清单：不缓存，限流
    location ~ ^/(stable|beta|internal)/latest\.json$ {
        include /etc/nginx/snippets/verthys-security-headers.conf;
        limit_req zone=manifest burst=20 nodelay;
        add_header Cache-Control "no-store, max-age=0" always;
        default_type application/json;
        try_files $uri =404;
    }

    # 不可变物料：长缓存，支持 Range
    location /releases/ {
        include /etc/nginx/snippets/verthys-security-headers.conf;
        limit_req zone=artifact burst=50 nodelay;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        types {
            application/octet-stream exe;
            text/plain sig;
            application/json json;
        }
        default_type application/octet-stream;
        try_files $uri =404;
    }

    # beta / internal 认证（M0 可选；按实际启用）
    # location = /beta/latest.json {
    #     include /etc/nginx/snippets/verthys-security-headers.conf;
    #     auth_basic "Verthys Beta";
    #     auth_basic_user_file /srv/verthys/secrets/beta.htpasswd;
    #     limit_req zone=manifest burst=20 nodelay;
    #     add_header Cache-Control "no-store, max-age=0" always;
    #     try_files $uri =404;
    # }

    location / {
        return 404;
    }

    access_log /var/log/nginx/verthys-updates.access.log;
    error_log  /var/log/nginx/verthys-updates.error.log warn;
}
```

注意：

1. `if` 仅用于 `return`，安全；不要用 `if` 做复杂逻辑。
2. `limit_req` 按 IP；CDN / 反向代理后需用 `real_ip` 模块还原真实 IP，否则所有请求共享 CDN 出口 IP。
3. 符号链接默认允许；确认 Nginx 未开启 `disable_symlinks`。
4. `Range` 由 Nginx 静态模块默认支持；`HEAD` 也默认支持。
5. 配置变更后 `nginx -t && systemctl reload nginx`。

### 5.5 TLS 签发

```bash
certbot --nginx -d updates.verthys.example --redirect
systemctl list-timers | grep certbot
```

- 首次签发后验证 `https://updates.verthys.example/stable/latest.json`。
- 确认自动续期 timer 存在；每月检查一次。
- M1 使用 CDN 证书时，源站仍需证书或仅允许 CDN 回源 IP。

### 5.6 备份

| 对象 | 方式 | 频率 | 保留 |
|---|---|---|---|
| 清单 / release manifest | rsync / 对象存储 | 每次发布 | 永久（或 1 年） |
| 安装包 / `.sig` | 对象存储 / 冷备 | 每次发布 | 最近 10 个 + 被引用版本 |
| Nginx / 证书配置 | 配置仓库 / 备份 | 变更时 | 永久 |
| 访问日志 | 轮转 / 归档 | 每日 | 90 天 |
| 服务器快照 | 云快照 | 每周 | 4 周 |

恢复演练：每季度从备份恢复一份清单 + 一个安装包，验证签名 / 哈希 / 客户端可检查。

---

## 6. 发布流水线

### 6.1 构建与签名顺序

```text
代码冻结
  → VERSION / sync_version
  → 质量门（master §6.1）
  → C 核心 / worker / Tauri 构建
  → Authenticode：verthys.dll → worker → Verthys.exe → NSIS 安装包
  → updater minisign：NSIS 安装包 → .sig
  → Manifest v2：sha256 / size / file_version / compatibility / rollout
  → 清单签名：JCS + minisign → latest.json
  → release-manifest.json + SBOM
  → 归档 / 上传
```

要求：

1. Authenticode 必须在 `.vsec` 完整性基准注入之后、打包之前签 DLL / worker / 主程序；NSIS 包在 Tauri 打包后签。
2. **签名顺序铁律**：NSIS 的 Authenticode 必须在 updater minisign 生成 `.sig` 之前完成。优先使用 Tauri `bundle.windows.signCommand` / `certificateThumbprint` 让 bundler 在签名后再生成 updater 产物；若手工后签 NSIS，必须删除旧 `.sig`、重新对最终字节签名，并重新生成清单。禁止在 `.sig` 生成后修改 NSIS。
3. 安装包 minisign 签名覆盖最终 NSIS 字节；签名后不得再修改安装包。
4. 清单签名覆盖“去掉 `manifest_signature` 的 JCS JSON”；签名后不得再改清单字段。
5. `release_id` 在构建开始时生成，贯穿清单、release manifest、日志、发布记录。
6. 所有哈希在构建机计算；服务器只做复核。
7. **哈希时序**：worker 副本哈希门在签名前；Authenticode 后重新计算最终 DLL / worker / 主程序哈希并写入 release manifest；发布哈希必须是最终已签名文件的哈希。

### 6.2 release_id 与物料命名

格式：`YYYYMMDD-HHMMSS-<version>-<gitsha8>`，例如 `20261022-090000-4.1.4-a1b2c3d4`。

| 物料 | 命名 |
|---|---|
| 安装包 | `Verthys_<version>_x64-setup.exe` |
| 安装包签名 | `Verthys_<version>_x64-setup.exe.sig` |
| 清单 | `latest.json` |
| 清单控制版本 | `<manifest_revision>/latest.json`（`YYYYMMDDTHHMMSSZ-<release_id>`） |
| 物料账本 | `release-manifest.json` |
| SBOM | `sbom.cdx.json` |
| 校验清单 | `checksums.txt`（必需；发布脚本据此校验） |

### 6.3 release-manifest.json

```json
{
  "schema_version": 1,
  "release_id": "20261022-090000-4.1.4-a1b2c3d4",
  "version": "4.1.4",
  "channels": ["stable"],
  "git_tag": "v4.1.4",
  "git_commit": "a1b2c3d4...",
  "build_profile": "production",
  "built_at": "2026-10-22T09:00:00Z",
  "builder": "K1Super",
  "installer": {
    "path": "releases/20261022-090000-4.1.4-a1b2c3d4/artifacts/Verthys_4.1.4_x64-setup.exe",
    "sha256": "<64 hex>",
    "size": 4865173,
    "file_version": "4.1.4",
    "minisign_key_id": "<key id>",
    "authenticode_sha256": "<cert thumbprint>",
    "authenticode_subject": "CN=..."
  },
  "sbom": {
    "path": "releases/20261022-090000-4.1.4-a1b2c3d4/artifacts/sbom.cdx.json",
    "sha256": "<64 hex>"
  },
  "manifests": [
    {
      "channel": "stable",
      "revision": "20261022T090000Z-20261022-090000-4.1.4-a1b2c3d4",
      "path": "channels/stable/20261022T090000Z-20261022-090000-4.1.4-a1b2c3d4/latest.json",
      "sha256": "<64 hex>",
      "signing_key_id": "<key id>"
    }
  ],
  "quality_gates": {
    "ctest": "pass",
    "vendor_hashes": "pass",
    "vitest": "pass",
    "vue_tsc": "pass",
    "e2e": "20/20"
  },
  "approvals": [
    { "role": "build", "name": "..." },
    { "role": "test", "name": "..." },
    { "role": "security", "name": "..." },
    { "role": "release", "name": "..." }
  ]
}
```

该文件用于审计与发布记录，不参与客户端安装决策；客户端只读 `latest.json`。`release-manifest.json` 中的路径均相对于更新根目录 `/srv/verthys/updates/`。同一安装包发布到多个渠道时，可为该 release 生成一份 `channels` 数组包含所有目标渠道的 release manifest；每个渠道的每个控制版本仍保留自己的已签名 `latest.json`，但物料只存一份。

### 6.4 上传与校验

上传目录结构：

```text
.incoming/<release_id>/
├── artifacts/
│   ├── Verthys_<version>_x64-setup.exe
│   ├── Verthys_<version>_x64-setup.exe.sig
│   └── sbom.cdx.json
├── release-manifest.json
├── checksums.txt
└── channels/
    └── <channel>/<manifest_revision>/latest.json
```

```bash
# 构建机 / CI 上传到服务器临时目录
rsync -av --chmod=0644 \
  build/updater/incoming/<release_id>/ \
  verthys@updates.verthys.example:/srv/verthys/updates/.incoming/<release_id>/

# 服务器侧校验
cd /srv/verthys/updates/.incoming/<release_id>
sha256sum -c checksums.txt
# 或逐项比对 release-manifest.json
```

要求：

1. 上传到 `.incoming/<release_id>`，校验通过后再拆分到 `releases/` 与 `channels/`。
2. 校验失败不得激活；保留 `.incoming` 供排查。
3. 上传用户只能写 `.incoming`、`releases`、`channels`；不能改 Nginx 配置。
4. 上传后对每个文件做服务端 SHA256 复核；与构建机记录一致。
5. 激活前从公网 URL 下载清单 / 安装包并复核签名 / 哈希；避免“内网正确、公网错误”。

### 6.5 原子激活

```bash
ROOT=/srv/verthys/updates
RELEASE_ID=20261022-090000-4.1.4-a1b2c3d4
CHANNEL=stable
MANIFEST_REVISION=20261022T090000Z-20261022-090000-4.1.4-a1b2c3d4
INCOMING="$ROOT/.incoming/$RELEASE_ID"

# 1. 物料就位（不可变）
install -d -m 0755 "$ROOT/releases/$RELEASE_ID"
mv "$INCOMING/artifacts" "$ROOT/releases/$RELEASE_ID/"
mv "$INCOMING/release-manifest.json" "$ROOT/releases/$RELEASE_ID/"
cp "$INCOMING/checksums.txt" "$ROOT/releases/$RELEASE_ID/"

# 2. 控制清单就位（不可变）
install -d -m 0755 "$ROOT/channels/$CHANNEL"
mv "$INCOMING/channels/$CHANNEL/$MANIFEST_REVISION" "$ROOT/channels/$CHANNEL/"

# 3. 原子切换渠道符号链接
ln -sfn "channels/$CHANNEL/$MANIFEST_REVISION" "$ROOT/.$CHANNEL.new"
mv -Tf "$ROOT/.$CHANNEL.new" "$ROOT/$CHANNEL"

# 4. 验证公网
curl -fsS "https://updates.verthys.example/$CHANNEL/latest.json" | jq .version

# 5. CDN purge（M1）
# curl -X POST ... /purge?url=https://updates.verthys.example/$CHANNEL/latest.json

# 6. 冒烟：下载安装包并校验
curl -fL -o /tmp/verthys-setup.exe "<installer_url>"
sha256sum /tmp/verthys-setup.exe
```

原子性说明：

- 符号链接替换是原子的；`stable/latest.json` 指向新的 `manifest_revision`。
- 物料与清单控制版本都不可变；暂停 / 调灰度 / 回滚只新增控制版本，不修改旧文件。
- 不删除旧 release / 旧 manifest_revision；回滚只需把符号链接指回上一控制版本。
- 清单内 URL 指向 `/releases/<release_id>/artifacts/...`，切换渠道不会改变物料内容。

### 6.6 回滚

| 场景 | 动作 | 目标时间 |
|---|---|---|
| 新版本安装失败率高 | 渠道符号链接切回上一 `manifest_revision` | < 5 分钟 |
| 安全事件 | 新 `manifest_revision`：`paused=true` + 撤回 release_id | < 5 分钟 |
| 清单错误 | 切回上一 `manifest_revision`；必要时重签 | < 10 分钟 |
| 物料损坏 | 切回上一 `manifest_revision`；重新上传修复版 | < 15 分钟 |
| CDN 缓存错误 | purge 清单 + 验证边缘 | < 10 分钟 |

回滚命令：

```bash
ROOT=/srv/verthys/updates
PREV_MANIFEST_REVISION=<previous_manifest_revision>
ln -sfn "channels/stable/$PREV_MANIFEST_REVISION" "$ROOT/.stable.new"
mv -Tf "$ROOT/.stable.new" "$ROOT/stable"
curl -fsS https://updates.verthys.example/stable/latest.json | jq .version
```

回滚后必须：

1. 从公网下载清单，确认 `release_id` / `version` 正确。
2. 用干净 VM 客户端检查更新，确认不再返回故障版本。
3. 记录回滚原因、操作人、时间、影响范围。
4. 保留故障版本物料至少 90 天用于审计。

### 6.7 密钥保管

| 密钥 | 位置 | 使用 | 轮换 |
|---|---|---|---|
| 安装包 minisign 私钥 | 构建机 / HSM / 离线介质 | 构建时签安装包 | 预留第二公钥；泄露即吊销 |
| 清单签名私钥 | 构建机 / HSM / 离线介质 | 发布时签清单 | 新旧 key id 并行 |
| Authenticode 证书 | EV/OV 证书 / 云签名 | 构建时签二进制 | 到期前 90 天续期 |
| SSH 发布密钥 | 构建机 / CI secret | 上传物料 | 90 天轮换 |
| beta / internal token | 密码库 / Access | 客户端鉴权 | 90 天轮换 |

规则：

- 服务器不持有任何签名私钥。
- 清单签名私钥与安装包签名私钥分离；泄露影响面不同。
- 私钥备份两份，异地离线；恢复流程双人执行。
- 所有密钥操作记录操作人、时间、目的、影响版本。

### 6.8 发布审批

| 角色 | 职责 | 最小人数 |
|---|---|---|
| 构建人 | 构建、签名、物料账本 | 1 |
| 测试人 | E2E、回归、证据表 | 1 |
| 安全复核 | 密钥、配置、日志、依赖 | 1 |
| 发布授权 | 批准渠道 / 灰度 / 回滚 | 1（不得与构建人同一人） |

紧急热修可以缩短审批，但必须保留事后记录；不得跳过签名与 E2E 核心负向用例。

---

## 7. 分发策略

### 7.1 渠道

| 渠道 | 受众 | 发布频率 | 认证 | 灰度 |
|---|---|---|---|---|
| `internal` | 开发 / 测试 / 内部 dogfood | 每次构建 | VPN / Access / Basic | 100% 内部 |
| `beta` | 试点用户 | 每个候选版本 | Bearer / Basic / Access | 1% → 10% → 50% |
| `stable` | 全量用户 | 稳定版本 | 匿名 | 1% → 10% → 50% → 100% |

渠道隔离要求：

1. 每个渠道独立 `latest.json`；不得用同一清单服务所有渠道。
2. `channel` 字段必须与端点一致；客户端不匹配即拒绝。
3. stable 清单不得包含 beta / internal 的 `release_id`；发布脚本校验。
4. beta / internal 的 token 不得写入 stable 安装包；token 在客户端配置中按渠道保存。
5. 渠道切换由用户在管理界面显式选择；stable 用户不能无意切到 beta。

### 7.2 灰度

#### 7.2.1 Bucket 计算

客户端首次运行生成随机 `install_id`（UUID v4），持久化在 `app_data_dir/updater/install_id`，不使用硬件指纹。灰度 bucket：

```text
bucket = SHA256(install_id + ":" + rollout.salt) mod 10000
eligible = bucket < rollout.percentage * 100
```

- `percentage = 1` → bucket 0 ~ 99 命中（1%）。
- `percentage = 100` → 全部命中。
- 同一 `install_id` + `salt` 结果稳定；换 `salt` 可重新分组。
- `install_id` 仅用于灰度与去重，不作为用户身份；不采集设备指纹。

#### 7.2.2 放量阶段

| 阶段 | 比例 | 最短观察 | 进入下一阶段的条件 |
|---|---:|---|---|
| 内部 | internal 100% | 1 个工作日 | 无 P0 / P1 故障；核心功能回归通过 |
| 试点 | beta 1% | 24 h | 安装成功 ≥ 99%；验签失败 0；回滚 < 0.5% |
| 小灰度 | stable 1% | 24 h | 安装成功 ≥ 99.5%；验签失败 0；回滚 < 0.5%；失败码无异常集中 |
| 中灰度 | stable 10% | 48 h | 安装成功 ≥ 99.5%；回滚 < 0.5%；无数据事故 |
| 大灰度 | stable 50% | 48 h | 同上；崩溃率 / 启动失败无上升 |
| 全量 | stable 100% | — | 同上；保留回滚窗口 |

阶段门说明：

- “最短观察”不是充分条件；样本量不足时延长观察。
- 任何 `sig_invalid` / `hash_mismatch` / `pe_version_mismatch` / `authenticode_invalid` > 0 立即暂停并调查。
- 任何数据事故（容器不可解锁 / 记录丢失）立即全渠道暂停 + 回滚。
- 放量通过重新生成同 `release_id` 的清单、修改 `rollout.percentage`、重签、原子替换实现；不重新上传安装包。

### 7.3 暂停、撤回、强制升级

| 动作 | 清单字段 | 客户端行为 | 服务端操作 |
|---|---|---|---|
| 暂停渠道 | `paused: true` | 视为无更新；已准备未安装的会话在安装前复查时放弃 | 重签清单 + 原子替换 |
| 撤回版本 | `revoked_release_ids: ["<release_id>"]` | 命中即 `INSTALL_REVOKED`；清理准备字节 | 重签清单 + 原子替换 |
| 强制升级 | `force_below: "<version>"` | 当前低于该版本时不可推迟；UI 只保留“立即更新” | 重签清单 |
| 桥接要求 | `min_version: "<version>"` | 当前低于该版本 → `BRIDGE_REQUIRED` | 发布桥接版本清单 |
| 回滚 | 渠道指针指回上一 `manifest_revision` | 新检查返回旧版本；已下载新版本但未安装的会话按“安装前复查”处理 | 原子切换符号链接 |

安装前复查规则：

- stable / beta / internal：`require_online_recheck_before_install = true`；安装前重新拉取清单，确认 `release_id` 仍存在、未暂停、未撤回、`rollout` 仍命中。
- 复查失败（离线 / 超时）：默认**不安装**，提示“无法确认发布状态，请联网后重试”；企业离线场景可通过配置放开，但需在发布记录中标注。
- local profile：不复查；本机物料目录为信任边界。

### 7.4 鉴权

| 渠道 | M0 | M1 |
|---|---|---|
| stable | 匿名 | 匿名 + WAF |
| beta | `auth_basic`（htpasswd）或 Bearer token | Cloudflare Access / 签名 URL / 短期 token |
| internal | VPN / IP allowlist + Basic | Access service token / mTLS |

要求：

1. token / 密码不在 stable 安装包中；按渠道单独配置。
2. 客户端使用 Windows DPAPI（`CryptProtectData`）保存 token；不以明文写入配置文件。
3. token 90 天轮换；泄露立即吊销并通知试点用户。
4. 认证失败返回 401，不泄露“用户是否存在”；日志不记录 `Authorization` 头。
5. 不采集用户身份；beta 账号只用于分发控制。
6. 若 beta / internal 物料本身需要保密，`/releases/` 也要加同样的鉴权或使用短期签名 URL；stable 物料保持公开。客户端下载时按渠道附带认证头。

### 7.5 下载

- 支持 `Range` / `Accept-Ranges: bytes`；客户端 P1 断点续传。
- 支持 `ETag` / `If-None-Match`；客户端可选，不用于安全判定。
- 安装包长缓存 + 不可变路径；CDN 命中率高。
- 大文件建议开启 `sendfile on; tcp_nopush on;`。
- 代理：客户端支持系统代理 / 显式代理；服务器不强制。
- 超时：连接 15 s、总时长 10 min；重试 3 次，退避 2 / 5 / 10 s + 抖动。
- 完整性：客户端下载后按 master §3.6 全量校验；服务端不提供“跳过校验”的参数。

---

## 8. 可观测性

### 8.1 事件上报 API

```
POST /v1/updater/events
Authorization: Bearer <ingest-token>
Content-Type: application/json
Content-Encoding: gzip（可选）
```

请求体：

```json
{
  "schema_version": 1,
  "install_id": "<uuid>",
  "events": [
    {
      "ts": "2026-10-22T09:00:00Z",
      "event_id": "<uuid>",
      "session_id": "<uuid>",
      "release_id": "20261022-090000-4.1.4-a1b2c3d4",
      "event": "install_success",
      "phase": "HealthCheck",
      "code": "",
      "severity": "info",
      "from_version": "4.1.3",
      "to_version": "4.1.4",
      "channel": "stable",
      "profile": "production",
      "os": "10.0.22631",
      "arch": "x64",
      "duration_ms": 1234,
      "attempt": 0,
      "bytes": 4865173,
      "hash_prefix": "a1b2c3d4e5f6",
      "bucket": 42
    }
  ]
}
```

约束：

| 项 | 限制 |
|---|---|
| 单请求事件数 | ≤ 100 |
| 单请求体积 | ≤ 256 KB（gzip 后） |
| 字段 | 白名单；未知字段丢弃 |
| 禁止 | 密钥、口令、容器路径、记录标题 / 内容、完整设备指纹、完整哈希 |
| 响应 | `202 Accepted`；`400` schema；`401` token；`413` 过大；`429` 限流 |
| 重试 | 客户端指数退避；失败不阻断更新 |
| 保留 | 90 天；聚合数据可更长 |
| 关闭 | 用户可关闭遥测；关闭后仅本地日志 |

### 8.2 采集形态

| 形态 | 组成 | 适用 |
|---|---|---|
| M0 本地 | Nginx access log + 客户端 JSONL + 手工汇总 | internal / beta 小规模 |
| M1 服务 | Nginx → 事件服务（Node / Go）→ PostgreSQL / ClickHouse | stable 灰度 |
| M1 无服务 | Cloudflare Worker + R2 / Logpush | 低运维 |
| M2 平台 | 事件服务 + 队列 + 数据仓库 + BI | 多产品 / 大规模 |

**stable 灰度前必须完成 M1 事件采集**；否则无法计算阶段门指标，不允许放量超过 beta。

### 8.3 大盘

必须包含：

1. 版本分布（按渠道 / OS / 日）。
2. 检查命中率、无更新率、失败率。
3. 下载成功率、平均 / P95 耗时、重试次数。
4. 验签 / 哈希 / PE / Authenticode 失败数（按 release_id）。
5. 安装成功率、回滚率、健康自检失败子项。
6. 失败码 TOP 20；按阶段切片。
7. 灰度 bucket 分布；各阶段设备数。
8. 事件上报量 / 丢弃量 / 延迟。

### 8.4 告警

| 告警 | 条件 | 动作 |
|---|---|---|
| 验签失败 | `sig_invalid + manifest_sig_invalid + pubkey_mismatch > 0`（5 分钟） | P1；暂停渠道；调查密钥 / 清单 / CDN |
| 哈希 / PE 失败 | `hash_mismatch + pe_version_mismatch + authenticode_invalid > 0` | P1；暂停；检查物料 |
| 安装失败率 | `install_failed / install_started > 1%`（30 分钟） | P1；暂停放量 |
| 回滚率 | `rolled_back / install_started > 2%`（1 小时） | P1；暂停渠道；回滚 |
| 下载失败率 | `download_failed / download_start > 5%`（15 分钟） | P2；检查 CDN / 源站 |
| 源站 5xx | > 0.1%（5 分钟） | P2；检查 Nginx / 磁盘 |
| 证书到期 | < 14 天 | P2；续期 |
| 清单过期 | 清单 `pub_date` 超过预期发布窗口 | P2；检查发布流水线 |
| 源站不可用 | 健康检查连续 3 次失败 | P1；切换备用 / CDN |
| 事件丢弃 | 丢弃率 > 1% | P3；扩容 / 限流 |

告警通道：邮件 / 企业 IM / 电话（P1）；记录告警 → 动作 → 恢复时间。

### 8.5 SLO

| 指标 | 目标 |
|---|---|
| stable 清单可用性 | ≥ 99.9% / 月 |
| 清单 P95 响应 | < 200 ms |
| 安装包下载 P95 首字节 | < 500 ms（CDN） |
| 事件 API 可用性 | ≥ 99.5% |
| 发布回滚时间 | < 5 分钟 |
| 证书续期成功率 | 100% |

### 8.6 隐私

- 不采集用户身份、容器路径、记录标题 / 内容、密钥、完整设备指纹。
- `install_id` 为随机 UUID，仅用于灰度与去重；不跨产品共享。
- 遥测默认开启但可关闭；关闭后仅本地日志；关闭状态写入配置，不上报。
- 数据保留 90 天；聚合数据可长期保留，但不得反推到个人。
- 发布隐私说明；安全事件（验签失败）可按合规单独评估是否强制上报。

---

## 9. 安全

### 9.1 威胁模型

| 威胁 | 影响 | 控制 | 残余 |
|---|---|---|---|
| 源站被攻破 | 替换清单 / 物料 / 拒绝服务 | 无私钥；清单签名；安装包签名；PE 版本；`revoked_release_ids`；文件只读 | 可拒绝服务；可回放旧签名清单（被版本 / PE / 撤回阻断） |
| CDN 缓存投毒 | 返回错误清单 / 物料 | 清单 `no-store`；物料不可变；TLS；签名校验；purge | 边缘节点故障 |
| DNS 劫持 | 指向恶意源 | DNSSEC；CAA；CT 监控；客户端 TLS 校验 | 注册商 / DNS 商被攻破 |
| TLS 配置错误 | 降级 / 中间人 | TLS 1.2+；HSTS；禁用弱 cipher；扫描 | 客户端系统信任链被攻破 |
| beta token 泄露 | 未授权获取 beta | 短期 token；限流；轮换；Access | 试点用户主动分享 |
| 事件接口滥用 | 成本 / 数据污染 | token；体积 / 速率限制；schema 校验；WAF | 分布式低速滥用 |
| 构建机被攻破 | 恶意签名 | 离线 / HSM 密钥；最小权限；SBOM；双人复核；构建审计 | 供应链高级攻击 |
| 内部人误操作 | 错发 / 覆盖 | 审批；原子发布；保留历史；回滚演练 | 人为绕过流程 |
| DDoS | 下载不可用 | CDN / WAF；限流；备用源 | 大流量攻击 |
| 日志泄露 | 隐私 / 凭证 | 脱敏；访问控制；保留期；不记录 Authorization | 运维导出 |

**残余风险说明（源站被攻破）**：攻击者没有私钥，无法伪造新清单 / 新安装包；但可以回放仍有效的已签名版本、拒绝服务或篡改访问日志。版本单调性、PE 版本、`revoked_release_ids` 与事件告警可以降低影响，但无法在“攻击者持续控制源站”时完全阻断已签名版本的提前 / 重复分发。彻底缓解需要透明日志、在线新鲜度证明或短期清单签名；本项目将其列为 S1 残余风险，通过源站最小权限、监控与快速回滚治理。

### 9.2 主机加固

- SSH 仅密钥、禁 root 密码、限制来源 IP（如可行）。
- UFW / 安全组仅 22 / 80 / 443。
- fail2ban；Nginx `limit_req`；`server_tokens off`。
- 自动安全更新；内核 / OpenSSL 及时重启。
- 文件权限：物料只读；发布用户与 Nginx 用户分离。
- 无编译工具 / 无数据库 / 无签名私钥在 Web 服务器。
- 日志轮转；磁盘监控。
- 时间同步。

### 9.3 WAF / 限流

M0：

- Nginx `limit_req`：清单 30 r/min/IP，物料 300 r/min/IP；burst 适度。
- 只允许 GET / HEAD。
- 请求体最大 1 MB（事件接口单独 256 KB）。
- 阻止路径穿越、异常 URL、超长 header。
- 可选：`naxsi` / ModSecurity CRS（谨慎，避免误伤）。

M1：

- Cloudflare / AWS WAF：地理 / ASN / 速率 / 已知恶意 IP；Bot 管理。
- 对 `/v1/updater/events` 单独限流。
- 开启 DDoS 防护；源站只允许 CDN 回源 IP。

### 9.4 密钥与凭证

- 签名私钥不在服务器；服务器只读公钥 / 证书。
- 发布 SSH key 90 天轮换；CI 使用短期 OIDC / 受限 key。
- beta / internal token 90 天轮换；泄露立即吊销。
- 事件 ingest token 随版本轮换；不作为强安全边界。
- 所有凭证不写入仓库、日志、镜像、聊天记录。

### 9.5 审计

| 事件 | 记录 |
|---|---|
| 发布 | release_id、版本、渠道、操作人、时间、物料哈希、审批 |
| 放量 | 比例、操作人、时间、阶段门指标 |
| 暂停 / 撤回 | 原因、操作人、时间、影响版本 |
| 回滚 | 原因、上一 release、操作人、时间、验证结果 |
| 密钥操作 | 类型、目的、操作人、时间、影响版本（不记录私钥） |
| 配置变更 | 文件、diff、操作人、时间 |

审计日志独立存储，保留至少 1 年；不可由发布用户删除。

### 9.6 事件响应

| 级别 | 示例 | 响应 |
|---|---|---|
| P0 | 数据事故、私钥泄露、恶意包 | 立即全渠道暂停；回滚；密钥轮换；通知；复盘 |
| P1 | 验签失败集中、安装失败 > 1%、回滚 > 2% | 暂停渠道；调查；回滚；修复 |
| P2 | 下载失败、源站 5xx、证书 < 14 天 | 限时修复；必要时切备用 |
| P3 | 事件丢弃、单设备异常 | 记录；下个迭代修复 |

---

## 10. 客户端迁移

### 10.1 迁移事实

当前 `4.1.3` 客户端内置 `http://127.0.0.1:8765/latest.json`。**它不会自动切换到服务器。** 任何服务器迁移都必须通过一次“桥接版本”的完整安装完成。

### 10.2 迁移路径

| 场景 | 路径 |
|---|---|
| 从未外发（推荐） | Phase L 只内部使用；第一次外发直接 production profile 完整安装包；不存在回环迁移 |
| 已有内部用户 | 发布 production profile 桥接版本；手动 / 内部渠道安装；之后走服务器 |
| 已有外部用户 | 桥接版本 + 明确通知；旧客户端无法自动切换；必须手动安装桥接包 |
| 企业批量 | MSI / GPO / Intune 分发桥接版本；后续走服务器 |

### 10.3 桥接版本要求

1. `production` profile，HTTPS 端点，无回环 / 明文许可。
2. 清单签名验证、安装包签名、SHA256、size、PE 版本、Authenticode。
3. `pending.json` + 健康自检 + R1 修复。
4. 渠道选择 + `rollout` + `paused` / `revoked` / `force_below`。
5. 事件上报 + 本地日志。
6. 代理 / 超时 / 重试 / Range。
7. beta / internal 鉴权头（DPAPI）。

### 10.4 首次服务器发布

1. 发布 internal 100%；内部机器验证。
2. 发布 beta 1%；试点用户验证。
3. 发布 stable 1%；观察 24 h。
4. 10% → 50% → 100%；每阶段门通过。
5. 保留上一 stable release 与清单；回滚演练完成。

### 10.5 旧客户端兼容

- 服务器清单的 `min_version` 设为桥接版本；低于该版本的客户端若支持字段，会提示桥接。
- 不支持 `min_version` 的旧客户端仍会按版本比较尝试安装；桥接包必须可安装、签名有效、PE 版本正确。
- 若旧客户端使用回环端点且无法访问服务器，只能手动安装桥接包；这是既有架构的硬限制，不伪装成“自动迁移”。

---

## 11. 测试与验收

### 11.1 Staging 环境

| 项 | 要求 |
|---|---|
| 域名 | `staging-updates.verthys.example` 或独立子域 |
| 证书 | 有效 TLS（可用 staging 证书 / Let's Encrypt） |
| 数据 | 独立目录 / 独立渠道；不与生产混用 |
| 客户端 | production profile 指向 staging；测试容器 |
| 监控 | 与生产同构；告警发到测试通道 |
| 清理 | 测试 release 不进入生产清单 |

### 11.2 测试用例

| # | 场景 | 预期 |
|---|---|---|
| S-01 | 清单获取 + 签名验证 | 200；签名通过；版本 / 渠道正确 |
| S-02 | 清单篡改 | 客户端拒绝；事件 `manifest_sig_invalid` |
| S-03 | 安装包哈希 / 签名篡改 | 客户端拒绝；不安装 |
| S-04 | 清单 404 / 500 / 超时 | 客户端重试 / `NETWORK`；不崩溃 |
| S-05 | Range 续传 | 断点续传成功；哈希最终一致 |
| S-06 | 缓存头 | 清单 no-store；物料 immutable；CDN 行为正确 |
| S-07 | 渠道隔离 | stable 不返回 beta；channel 不匹配拒绝 |
| S-08 | 暂停 | `paused=true` 后无更新；准备中的会话安装前复查放弃 |
| S-09 | 撤回 | 命中 `revoked_release_ids` → `INSTALL_REVOKED` |
| S-10 | 灰度 | 1% / 10% / 50% / 100% bucket 分布符合预期 |
| S-11 | 指针回滚 | 5 分钟内切回上一版本；客户端检查到旧版本 |
| S-12 | 清单回滚 | 旧清单重签 / 原子替换；客户端正常 |
| S-13 | CDN purge | 清单更新在 1 分钟内可见 |
| S-14 | 认证 | beta 无 token 401；有 token 200；错误 token 401 |
| S-15 | 限流 | 超限 429；正常用户不受影响 |
| S-16 | 事件接口 | 202；超大 / 非法 schema 拒绝；限流生效 |
| S-17 | 负载 | 1000 并发下载；10k 清单请求 / 分钟；错误率 < 0.1% |
| S-18 | 源站故障 | CDN / 备用源可切换；或明确降级 |
| S-19 | 证书过期模拟 | 客户端拒绝；告警触发 |
| S-20 | 密钥轮换 | 新 key 签清单 / 安装包；旧客户端按密钥集验证 |
| S-21 | 干净 VM E2E | 正向 / 负向 / 回滚 / 暂停 / 撤回全部通过 |
| S-22 | 安全扫描 | TLS A 级；无目录列表；无版本泄露；WAF 规则生效 |

### 11.3 负载与容量测试

- 清单：10,000 请求 / 分钟，P95 < 200 ms。
- 安装包：1,000 并发下载 5 MB 文件；无 5xx；带宽打满时排队可控。
- 事件：1,000 事件 / 秒短时突发；202 / 429 行为符合设计。
- 源站磁盘：发布 100 个 release 后仍有 20% 余量。
- CDN：缓存命中率 > 90%（物料）；清单绕过。

### 11.4 故障演练

| 演练 | 方法 | 通过标准 |
|---|---|---|
| 源站宕机 | 停止 Nginx / 关机 | 告警触发；CDN 缓存仍可下载；清单按设计失败 |
| DNS 故障 | 切换解析 | 客户端失败可诊断；恢复后自动恢复 |
| 证书过期 | staging 使用过期证书 | 客户端拒绝；告警；续期流程可用 |
| 清单损坏 | 上传错误签名清单 | 客户端拒绝；回滚清单 |
| 指针误切 | 切到错误 release | 5 分钟内切回；审计记录 |
| 私钥泄露演练 | 模拟吊销 / 轮换 | 新 key 并行；旧 key 吊销；桥接版本可发布 |
| 事件管道中断 | 停事件服务 | 更新不受影响；本地日志保留；恢复后补传 |

### 11.5 验收标准

1. S-01 ~ S-22 全部通过；证据归档。
2. 负载测试达到 §11.3；无 5xx 雪崩。
3. 回滚演练 < 5 分钟；客户端验证通过。
4. 密钥轮换演练通过；旧客户端可验新签名。
5. 监控 / 告警 / 值班就绪；SLO 可查询。
6. 安全扫描无高危；TLS A 级；无目录列表。
7. 客户端 readiness C01 ~ C12 全部完成。
8. 隐私说明 / 遥测开关 / 保留期已确认。

---

## 12. 运维 Runbook

### 12.1 日常

| 频率 | 检查 |
|---|---|
| 每日 | 告警；源站磁盘；证书剩余天数；备份完成；事件上报量 |
| 每周 | Nginx 错误日志；访问异常；发布记录；账号 / token 有效期 |
| 每月 | 证书续期演练；备份恢复抽样；依赖安全公告；日志保留清理 |
| 每季度 | 回滚演练；密钥轮换评估；容量评估；权限复核 |
| 每半年 | 灾备演练；安全复核；文档复核 |

### 12.2 发布

1. 构建机执行 production 构建 + 签名 + 清单 + release manifest。
2. 上传到 `.incoming/<release_id>`。
3. 服务端校验哈希；公网下载复核签名。
4. 物料移入 `releases/<release_id>`；控制清单移入 `channels/<channel>/<manifest_revision>`。
5. 原子切换渠道符号链接。
6. 公网检查清单；CDN purge；下载冒烟。
7. 记录发布台账；通知值班。
8. 按 §7.2 放量。

### 12.3 暂停

```bash
# 1. 构建机生成新的 manifest_revision（paused=true），重新签名
# 2. 上传到 channels/stable/<new_manifest_revision>/latest.json
# 3. 原子切换符号链接
ROOT=/srv/verthys/updates
NEW_MANIFEST_REVISION=<new_manifest_revision>
ln -sfn "channels/stable/$NEW_MANIFEST_REVISION" "$ROOT/.stable.new"
mv -Tf "$ROOT/.stable.new" "$ROOT/stable"

# 4. 公网验证
curl -fsS https://updates.verthys.example/stable/latest.json | jq '.paused, .release_id'
```

要求：暂停清单必须重新签名；不得手工编辑线上 JSON；不得修改旧 `manifest_revision`。

### 12.4 回滚

见 §6.6。回滚后：

1. 公网验证清单版本 / release_id。
2. 干净 VM 客户端检查更新，确认不再返回故障版本。
3. 检查事件大盘，确认安装失败 / 回滚停止上升。
4. 记录原因、影响、操作人、时间。
5. 保留故障物料 90 天。

### 12.5 证书续期

```bash
certbot renew --dry-run
certbot renew
systemctl reload nginx
curl -vI https://updates.verthys.example/stable/latest.json 2>&1 | grep -i expire
```

- 自动续期失败时手动执行；检查 DNS / 80 端口 / webroot。
- 续期后验证证书链、OCSP、HSTS。

### 12.6 CDN purge

```bash
# 以 Cloudflare 为例
curl -X POST "https://api.cloudflare.com/client/v4/zones/<zone>/purge_cache" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  --data '{"files":["https://updates.verthys.example/stable/latest.json"]}'
```

- 只 purge 清单；物料不可变，不需要 purge。
- purge 后从多个地区验证清单版本。

### 12.7 坏版本处理

1. 立即 `paused=true` 或切回上一 release。
2. 若已大量安装：发布修复版；必要时 `force_below` 推送修复。
3. 若涉及数据损坏：停止分发；发布修复工具；通知用户备份容器。
4. 复盘：根因、检测、响应、改进；更新 E2E / 监控。

### 12.8 密钥泄露

1. 停止发布；全渠道暂停。
2. 确认泄露范围（安装包签名 / 清单签名 / Authenticode）。
3. 生成新密钥；更新客户端可信 key 集（桥接版本）。
4. 用新密钥重签清单 / 安装包；旧密钥吊销。
5. 发布桥接版本；通知用户；监控异常安装。
6. 复盘；更新密钥保管流程。

### 12.9 事件管道故障

- 更新链路不依赖事件接口；事件失败不阻断更新。
- 客户端本地日志保留 7 天；恢复后可补传（若实现）。
- 大盘缺失期间，放量暂停；恢复后再评估。

---

## 13. 容量与成本

### 13.1 容量公式

```text
月下载流量 ≈ 安装包大小 × 月更新设备数 × (1 + 重试率)
存储 ≈ release 数 × 安装包大小 × 副本数
清单请求 ≈ 日活设备数 × 每日检查次数
```

示例（5 MB 安装包）：

| 设备数 | 月更新一次流量 | 存储（10 版本 × 2 副本） | 清单请求（2 次/日） |
|---:|---:|---:|---:|
| 1,000 | 5 GB | 100 MB | 60k / 月 |
| 10,000 | 50 GB | 100 MB | 600k / 月 |
| 100,000 | 500 GB | 100 MB | 6M / 月 |

### 13.2 成本粗算

| 形态 | 固定成本 | 流量成本 | 备注 |
|---|---|---|---|
| M0 VPS | $20 ~ $60 / 月 | 包含在 VPS 带宽内（超额另计） | 适合 < 10k 设备 |
| M1 对象存储 + CDN | $5 ~ $50 / 月存储 | $0.01 ~ $0.10 / GB（因地区） | 适合 > 10k 设备 |
| 事件服务 | $10 ~ $100 / 月 | 视日志量 | 可用托管数据库 |

> 以上为量级参考，不是报价；实际以云厂商账单为准。成本优化：不可变缓存、CDN、压缩清单、避免重复下载、限制重试。

### 13.3 扩容触发

- 带宽持续 > 70% 峰值；
- 清单 P95 > 200 ms；
- CDN 命中率 < 80%；
- 源站磁盘 > 70%；
- 事件延迟 > 5 分钟；
- 单点故障不可接受。

---

## 14. 上线检查清单

### 14.1 客户端

- [ ] production profile，HTTPS，无回环 / 明文许可
- [ ] 清单签名 + 密钥集
- [ ] 安装包签名 + SHA256 + size + PE 版本
- [ ] Authenticode 验证
- [ ] 渠道 + rollout + paused / revoked / force_below
- [ ] 安装前在线复查
- [ ] pending marker + 健康自检
- [ ] R1 修复 / LKG
- [ ] 事件上报 + 本地日志
- [ ] 代理 / 超时 / 重试 / Range
- [ ] beta / internal 鉴权（DPAPI）

### 14.2 构建 / 签名

- [ ] 安装包 minisign 私钥受控
- [ ] 清单签名私钥受控
- [ ] Authenticode 证书 / 时间戳可用
- [ ] release manifest / SBOM 生成
- [ ] 质量门 G0 ~ G8 全绿
- [ ] E2E 20/20 + 回归附加
- [ ] 物料哈希可复核

### 14.3 服务器

- [ ] 域名 / DNS / CAA / DNSSEC
- [ ] TLS 1.2+ / HSTS / 证书自动续期
- [ ] Nginx 配置 / 安全头 / 限流
- [ ] 目录 / 权限 / 符号链接
- [ ] 防火墙 / fail2ban / 自动更新
- [ ] 备份 / 快照 / 恢复演练
- [ ] 监控 / 告警 / 值班
- [ ] 事件接口 / 大盘 / 保留期
- [ ] beta / internal 认证
- [ ] WAF / DDoS（M1）

### 14.4 发布治理

- [ ] 发布审批 / 双人复核
- [ ] 回滚演练 < 5 分钟
- [ ] 暂停 / 撤回演练
- [ ] 密钥轮换演练
- [ ] 证书过期演练
- [ ] 事件管道中断演练
- [ ] 隐私说明 / 遥测开关
- [ ] 发布台账 / 审计日志

### 14.5 签字

| 角色 | 姓名 | 日期 | 结论 |
|---|---|---|---|
| 构建 | | | |
| 测试 | | | |
| 安全 | | | |
| 发布授权 | | | |

---

## 15. 风险

| # | 风险 | 影响 | 缓解 | 残余 |
|---|---|---|---|---|
| SR-1 | 单机单点 | stable 不可用 | M1 CDN / 备用源；快照 | 恢复时间 |
| SR-2 | 源站被攻破 | 拒绝服务 / 回放旧清单 | 无私钥；签名；PE；撤回；文件只读 | DoS |
| SR-3 | CDN 缓存错误 | 旧清单 / 旧包 | 清单 no-store；purge；多地区验证 | 边缘延迟 |
| SR-4 | 证书过期 | 全量检查失败 | 自动续期；30 / 14 / 7 天告警 | 配置错误 |
| SR-5 | beta token 泄露 | 未授权 beta | 短期 token；轮换；限流 | 分享 |
| SR-6 | 事件接口滥用 | 成本 / 数据污染 | token；限流；schema；WAF | 低速滥用 |
| SR-7 | 构建机被攻陷 | 恶意签名 | HSM / 离线；双人；SBOM；审计 | 高级供应链攻击 |
| SR-8 | 灰度样本不足 | 误判 | 最短观察 + 样本量；延长观察 | 统计误差 |
| SR-9 | 回滚物料缺失 | 无法回滚 | 保留 10 个 release；引用检查；备份 | 人为删除 |
| SR-10 | 成本超预算 | 账单 | 容量监控；CDN 优化；限额 | 突发流量 |
| SR-11 | 厂商锁定 | 迁移成本 | 静态文件 + 标准 HTTP；对象存储抽象 | 配置差异 |
| SR-12 | 旧客户端无法迁移 | 用户停留在回环 | 桥接版本 + 明确通知；不伪装自动 | 手动成本 |

---

## 附录 A：发布脚本骨架

```bash
#!/usr/bin/env bash
# scripts/server/publish_release.sh
# 用法：publish_release.sh <release_id> <channel> <manifest_revision> <incoming_dir>
set -euo pipefail

ROOT="/srv/verthys/updates"
RELEASE_ID="${1:?release_id}"
CHANNEL="${2:?channel}"
MANIFEST_REVISION="${3:?manifest_revision}"
INCOMING="${4:?incoming dir}"

case "$CHANNEL" in
  stable|beta|internal) ;;
  *) echo "invalid channel: $CHANNEL" >&2; exit 1 ;;
esac

# 1. 校验 incoming
test -f "$INCOMING/channels/$CHANNEL/$MANIFEST_REVISION/latest.json"
test -f "$INCOMING/release-manifest.json"
test -f "$INCOMING/checksums.txt"
[ -n "$(find "$INCOMING/artifacts" -maxdepth 1 -name 'Verthys_*.exe' -type f -print -quit)" ]
[ -n "$(find "$INCOMING/artifacts" -maxdepth 1 -name 'Verthys_*.exe.sig' -type f -print -quit)" ]
( cd "$INCOMING" && sha256sum -c checksums.txt )

# 2. 物料与控制清单就位（均不可变）
install -d -m 0755 "$ROOT/releases" "$ROOT/channels/$CHANNEL"
test ! -e "$ROOT/releases/$RELEASE_ID"
test ! -e "$ROOT/channels/$CHANNEL/$MANIFEST_REVISION"
if [ -e "$ROOT/$CHANNEL" ] && [ ! -L "$ROOT/$CHANNEL" ]; then
  echo "channel path exists and is not a symlink: $ROOT/$CHANNEL" >&2
  exit 1
fi

install -d -m 0755 "$ROOT/releases/$RELEASE_ID"
mv "$INCOMING/artifacts" "$ROOT/releases/$RELEASE_ID/"
mv "$INCOMING/release-manifest.json" "$ROOT/releases/$RELEASE_ID/"
cp "$INCOMING/checksums.txt" "$ROOT/releases/$RELEASE_ID/"

mv "$INCOMING/channels/$CHANNEL/$MANIFEST_REVISION" "$ROOT/channels/$CHANNEL/"

chown -R verthys:verthys "$ROOT/releases/$RELEASE_ID" "$ROOT/channels/$CHANNEL/$MANIFEST_REVISION"
find "$ROOT/releases/$RELEASE_ID" -type d -exec chmod 0755 {} +
find "$ROOT/releases/$RELEASE_ID" -type f -exec chmod 0644 {} +
find "$ROOT/channels/$CHANNEL/$MANIFEST_REVISION" -type d -exec chmod 0755 {} +
find "$ROOT/channels/$CHANNEL/$MANIFEST_REVISION" -type f -exec chmod 0644 {} +

# 3. 原子切换渠道
ln -sfn "channels/$CHANNEL/$MANIFEST_REVISION" "$ROOT/.$CHANNEL.new"
mv -Tf "$ROOT/.$CHANNEL.new" "$ROOT/$CHANNEL"

# 4. 公网验证
curl -fsS "https://updates.verthys.example/$CHANNEL/latest.json" \
  | jq -e --arg r "$RELEASE_ID" '.release_id == $r' >/dev/null

# 5. CDN purge（按实际云厂商）
# curl -X POST ... --data "{\"files\":[\"https://updates.verthys.example/$CHANNEL/latest.json\"]}"

echo "[OK] published $RELEASE_ID ($MANIFEST_REVISION) to $CHANNEL"
```

要求：

- 服务器侧不签名；只校验和切换。
- `checksums.txt` 由构建机生成，覆盖安装包、`.sig`、清单、release manifest、SBOM；归档到 release 目录用于溯源，拆分后的逐文件校验以 `release-manifest.json` 为准。
- 脚本失败不得切换渠道；`.incoming` 保留供排查。
- 发布用户只能执行该脚本 / 受限 sudo；不能直接改 Nginx。
- 脚本中的 `chown` / `mv` 需要发布用户具备受限 sudo 权限；不要给完整 root shell。

## 附录 B：生产清单示例（stable）

```json
{
  "schema_version": 2,
  "release_id": "20261022-090000-4.1.4-a1b2c3d4",
  "version": "4.1.4",
  "channel": "stable",
  "pub_date": "2026-10-22T09:00:00.000Z",
  "notes": "安全修复与稳定性改进。",
  "notes_sections": [
    { "type": "security", "items": ["修复更新校验边界"] },
    { "type": "fixed", "items": ["修复 worker 就绪竞态"] }
  ],
  "min_version": "4.1.0",
  "force_below": "4.0.0",
  "rollout": { "percentage": 1, "salt": "2026-10-22-a1b2c3d4" },
  "paused": false,
  "revoked_release_ids": [],
  "compatibility": {
    "abi": { "min": "0x000B", "max": "0x000B" },
    "container": { "min": 3, "max": 3 },
    "os": { "min": "10.0.17763" },
    "webview2": { "min": "120.0.0" }
  },
  "platforms": {
    "windows-x86_64": {
      "url": "https://updates.verthys.example/releases/20261022-090000-4.1.4-a1b2c3d4/artifacts/Verthys_4.1.4_x64-setup.exe",
      "signature": "<base64 minisign signature>",
      "sha256": "<64 位小写十六进制>",
      "size": 4865173,
      "file_version": "4.1.4",
      "authenticode": { "required": true, "subject": "CN=...", "sha256": "<cert thumbprint>" }
    },
    "windows-x86_64-nsis": {
      "url": "https://updates.verthys.example/releases/20261022-090000-4.1.4-a1b2c3d4/artifacts/Verthys_4.1.4_x64-setup.exe",
      "signature": "<base64 minisign signature>",
      "sha256": "<64 位小写十六进制>",
      "size": 4865173,
      "file_version": "4.1.4",
      "authenticode": { "required": true, "subject": "CN=...", "sha256": "<cert thumbprint>" }
    }
  },
  "manifest_signature": {
    "alg": "minisign",
    "key_id": "<key id>",
    "signature": "<base64 minisign signature over JCS(manifest without manifest_signature)>"
  }
}
```

## 附录 C：事件 API 响应

```json
{
  "accepted": 42,
  "dropped": 0,
  "server_time": "2026-10-22T09:00:01Z"
}
```

## 附录 D：回滚检查清单

- [ ] 选择上一稳定 `release_id`
- [ ] 原子切换渠道符号链接
- [ ] 公网验证 `version` / `release_id`
- [ ] CDN purge 清单
- [ ] 干净 VM 客户端检查更新
- [ ] 确认故障版本不再返回
- [ ] 事件大盘确认失败率下降
- [ ] 记录原因 / 影响 / 操作人 / 时间
- [ ] 保留故障物料 90 天
- [ ] 通知相关方

## 附录 E：修订记录

| 版本 | 日期 | 变更 | 作者 |
|---|---|---|---|
| v1.0 | 2026-10-22 | 首次发布：M0 / M1 / M2 架构、Nginx 基线、发布流水线、灰度 / 暂停 / 撤回、事件聚合、安全、迁移、验收、Runbook | K1Super |

