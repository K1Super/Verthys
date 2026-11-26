/*
 * background_patrol.rs — 后台模块巡检线程
 *
 * 子模块：
 *   - persistence：巡检状态持久化（DPAPI + HMAC + schema 版本）
 *   - state：巡检状态与哈希基线管理器
 *   - patrol：巡检管理器、线程上下文、单次巡检与威胁管线
 *   - watchdog：看门狗、巡检主循环、动态频率与抽样
 *   - os：平台原语（模块枚举/缓解策略/空闲时间/线程优先级）与路径时间辅助
 *   - emergency：独立应急响应通道、后端熔断与审计
 *
 * 要点：
 *   1. 动态频率 + 无窗口随机巡检（10~40 秒随机抖动 + 系统空闲时间结合）
 *      - 消除固定 30 秒周期的规律性，攻击者无法在巡检间隙规避
 *      - 系统空闲时降低频率（省 CPU），活跃时提高频率（覆盖攻击窗口）
 *   2. 系统目录模块使用哈希基线库，杜绝位置信任
 *      - 预计算 System32/SysWOW64 下所有合法 DLL 的 SHA-256 哈希
 *      - 巡检时对系统目录模块的哈希进行匹配，被替换的 DLL 即便在系统目录下也被检出
 *   3. 检测状态加密持久化（HMAC 保护 + DPAPI 加密），绑定设备与安装
 *      - 连续检测计数、触发历史、巡检总次数持久化到受保护文件
 *      - 即使重启，累积计数不丢失，已触发的信号保持有效
 *   4. 巡检看门狗，确保线程存活并具备自愈能力
 *      - 每 5 秒检查巡检线程心跳：巡检线程在睡眠期每秒、哈希扫描期每
 *        模块更新心跳，15 秒静默阈值只捕获真实卡死，不受 10~80 秒
 *        动态巡检间隔影响
 *      - 连续重启失败后强制触发应急熔断（直接销毁 Worker 会话）
 *   5. 后端的独立应急响应通道，不依赖前端
 *      - 检测到威胁时直接通过 AppState::set_session(None) 销毁 Worker
 *      - 前端事件仅作为辅助通知，后端强制措施先于前端执行
 *   6. 进程完整性监控，防止巡检被注入或终止
 *      - SetProcessMitigationPolicy 启用 ProcessSignaturePolicy / ProcessImageLoadPolicy
 *   7. catch_unwind 包裹单次巡检，防 panic 退出
 *      - 单次扫描 panic 不会导致线程退出，看门狗仍可恢复
 *   8. 完整校验抽样复核
 *      - 每轮随机抽样少量受信位置已加载模块做签名复核（部分
 *        Fisher-Yates 抽样，抽样期推进心跳），失效进入威胁管线
 */

mod emergency;
mod os;
mod patrol;
mod persistence;
mod state;
mod watchdog;

#[cfg(test)]
mod tests;

pub use patrol::BackgroundPatrol;

/* ====================================================================== *
 *  常量                                                                   *
 * ====================================================================== */

/// 动态频率下限（秒）
const PATROL_MIN_INTERVAL_SECS: u64 = 10;
/// 动态频率上限（秒）
const PATROL_MAX_INTERVAL_SECS: u64 = 40;
/// 系统空闲超过此阈值（秒）时降低巡检频率（空闲倍率 2x）
const IDLE_THRESHOLD_SECS: u64 = 300; // 5 分钟
/// 系统活跃（空闲 < 此阈值）时使用最小间隔
const ACTIVE_THRESHOLD_SECS: u64 = 30;

/// 连续检测阈值：同一未知模块在连续 N 次巡检中出现即触发应急信号。
const CONSECUTIVE_TRIGGER_THRESHOLD: u32 = 3;

/// 完整校验抽样复核：每轮巡检最多抽样的受信位置模块数。
/// 抽样数量与巡检周期（10~40s）共同约束签名复核的网络/CPU 开销上限。
const INTEGRITY_SAMPLE_PER_ROUND: usize = 3;

/// 环形缓冲区最大条目数。防止攻击者注入海量不同路径模块导致无界内存增长。
const RING_BUFFER_MAX_ENTRIES: usize = 256;

/// 看门狗检查间隔（秒）
const WATCHDOG_CHECK_SECS: u64 = 5;
/// 心跳超时阈值（秒）：巡检线程在睡眠期按秒、哈希扫描期按模块推进心跳，
/// 该阈值必须显著大于节拍间隔（秒级），只表示真实卡死而非巡检间隔。
const HEARTBEAT_TIMEOUT_SECS: u64 = 15;
/// 睡眠期心跳节拍/停止标志检查粒度（秒）
const HEARTBEAT_BEAT_SECS: u64 = 1;
/// 看门狗连续重启失败上限：超过后强制触发应急熔断
const WATCHDOG_MAX_RESTART_FAILURES: u32 = 3;

/// 空闲治理：状态指纹不变时跳过磁盘持久化的强制兜底周期。
/// patrol_count 每次巡检 +1（不参与指纹），每 N 次巡检强制落盘一次，
/// 确保计数的漂移丢失上界为 N 次巡检。
const PATROL_FORCE_PERSIST_INTERVAL: u32 = 64;

/// 应急信号：未知第三方 DLL 注入（镜像 C 端 EMERG_SIG_UNKNOWN_DLL = 0x0010）。
const EMERG_SIG_UNKNOWN_DLL: u32 = 0x0010;
/// 匿名故障码：注入阻断（镜像 C 端 EMERGENCY_CODE_INJECTION_BLOCK = 0xE0002u）。
const EMERG_CODE_INJECTION_BLOCK: u32 = 0xE0002;

/// 前端监听的应急事件名。前端 listen 此事件后执行辅助通知（熔断由后端直接执行）。
pub const EMERGENCY_EVENT_NAME: &str = "verthys://security-emergency";

/// HMAC 密钥派生盐值（公开常量，不增加安全性，仅防止与其它用途的 PBKDF2 派生冲突）
const PATROL_HMAC_SALT: &[u8] = b"verthys_patrol_state_hmac_salt_v1";

/// 巡检状态模式版本。
///
/// 当前语义下签名有效的第三方注入模块不计入 `counts`/`triggered`，
/// 仅未签名模块进入应急管线。低于当前版本的状态按其旧语义记录，
/// 加载时直接丢弃重建。
const PATROL_STATE_SCHEMA_VERSION: u32 = 2;
