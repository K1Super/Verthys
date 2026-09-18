# cache/ — Verthys 缓存层（分层架构）

本目录按职责分层组织。**对外公共 API 仅由 `composition/` 两个门面提供**，
外部模块禁止深入导入其他子目录（领域类/原语/协调器均为内部实现细节，
其签名变更不受对外兼容承诺保护）。

## 分层结构与职责

```
cache/
├── composition/                  组合根 + 对外绑定层（唯一公共 API 入口）
│   ├── verthys-cache.ts            缓存层门面：initVerthysCache() 组合根装配 +
│   │                             31 个显式包装函数（ensureDomain fail-fast）
│   └── verthys-flush.ts            冲刷队列门面：VerthysFlushService 实例化 + API 绑定
├── domain/                       领域层（核心逻辑，依赖注入，可测试）
│   ├── verthys-cache-domain.ts     VerthysCacheDomain：五大缓存 + 代际令牌扫描 +
│   │                             互斥锁 + 删除过滤（依赖经构造函数注入）
│   └── verthys-flush-service.ts    VerthysFlushService：串行冲刷队列 + 防抖合并 +
│                                 超时兜底 + ID 复用防护
├── coordination/                 缓存协调器（业务侧统一增删改入口）
│   ├── cache-coordinator.ts      事件驱动单例：record:add/remove/update → 三层同步
│   └── batch-cache-coordinator.ts 批量协调器：插件化写入器 + 背压 + 重试回灌
├── concurrency/                  并发与数据结构原语（零业务依赖，可独立复用）
│   ├── async-mutex.ts            FIFO 异步互斥锁
│   ├── lru-cache.ts              泛型 LRU（淘汰回调）
│   └── typed-event-emitter.ts    零依赖类型化事件发射器（浏览器构建无 Node events）
└── shared/                       跨层共享工具
    └── base64-size.ts            Base64 字节大小精确估算（单一权威源）
```

## 依赖规则（单向，禁止反向）

```
composition ──→ domain ──→ concurrency / shared
     │             │
     │             └──→ composition/verthys-flush（唯一例外：快照注册通道
     │                     setSnapshotProvider，既有单向边，无回边）
     └──→ domain + core/background-tasks（仅 stopBackgroundTasks 钩子注入）

coordination ──→ composition/verthys-cache（业务侧消费门面）
             ──→ concurrency / shared
```

- `domain/`、`concurrency/`、`shared/` 禁止导入 `coordination/` 与业务模块；
- `concurrency/`、`shared/` 零内部依赖（仅标准 API / Vue）；
- 循环依赖治理见 `composition/verthys-cache.ts` 头注（残余双向边
  verthys-cache ↔ background-tasks 的运行时安全性论证）。

## 初始化契约

`initVerthysCache()`（幂等）由 `app/bootstrap.ts` 在 `createApp` 之前调用，
完成组合根装配（VerthysCacheApi 适配器、KeyStateForCache 最小接口、共享删除
集合、中止/停止钩子、快照提供者注册）。全部门面函数经 `ensureDomain()`
守卫，未初始化 fail-fast 抛错，杜绝静默 undefined。

## 关键不变量（跨层共识）

1. **删除过滤单一权威源**：`pendingDeletionIds` / `committedDeletionIds`
   由 VerthysFlushService 持有，经组合根注入 VerthysCacheDomain 同一 Set 实例；
   任何层不得自建副本（防删除复活）。
2. **扫描过滤三条件**：待删 ID 在扫描合并 / 各读取路径强制过滤，直至
   flush 磁盘验证成功才解除。
3. **单游标后端**：Rust `verthys_scan_open` 自动顶替旧游标；扫描令牌失效
   按"属主保护"收尾（见 verthys-cache-domain 头注评审修复 3+5）。
4. **明文密钥零填充**：模块密钥以 Uint8Array 存储并在清除时安全覆写
   （方案 7.1/7.2），`clearAllVerthysCaches` 首项清零密钥。
