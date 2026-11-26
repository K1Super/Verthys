/* GMK 全局主密钥状态（会话级，worker 内存中持有）
 *
 * 设计：
 *   - GMK 永不出 worker 子进程
 *   - 前端通过 IPC 请求派生子密钥
 *   - worker 退出（Drop）或 clear_global_key 时自动清零
 */

use std::cell::RefCell;

/// 验证器明文常量（32 字节，AES-GCM 加密后 = 48 字节含 tag）
/// 以版本标识 + 尾下划线补齐定长 32 字节
pub(super) const VERIFIER_PLAIN: &[u8; 32] = b"VERTHYS_GLOBAL_KEY_VERIFIER_v2__";
/// 验证器 AES-GCM 附加数据
#[allow(dead_code)]
const VERIFIER_AD: &[u8] = b"VERTHYS_GLOBAL_VERIFIER_v1";

/// 全局密钥记录类型与名称（与前端 TYPE_GLOBAL_KEY / "global-key" 对齐）
pub(super) const TYPE_GLOBAL_KEY: u8 = 0x10;
pub(super) const GLOBAL_KEY_NAME: &str = "global-key";
/// 记录固定长度：salt(32) + nonce(12) + verifierCt(48) + binHash(32)
pub(super) const GLOBAL_KEY_RECORD_LEN: usize = 124;
/// 类型索引分页大小（记录数极少，单页即可覆盖）
pub(super) const GLOBAL_KEY_PAGE_SIZE: u64 = 64;
/// 候选记录上限：超过视为容器异常，拒绝改钥，避免无界遍历
pub(super) const GLOBAL_KEY_MAX_CANDIDATES: usize = 256;

/// 本地错误码（与 verthys.h 对齐；避免跨模块常量耦合）
pub(super) const CODE_OK: u32 = 0x00000000;
pub(super) const CODE_AUTH: u32 = 0x00000002;
pub(super) const CODE_NOTFOUND: u32 = 0x00000003;
#[cfg(test)]
pub(super) const CODE_IO: u32 = 0x00000008;
pub(super) const CODE_CORRUPT: u32 = 0x00000009;
pub(super) const CODE_RESOURCE_LIMIT: u32 = 0x0000000F;

/// 派生结果：GMK 与待落盘记录（均未写入 thread_local 槽）
pub(super) struct GmkMaterial {
    pub(super) gmk: zeroize::Zeroizing<[u8; 32]>,
    pub(super) record: Vec<u8>,
}

/// 写入 GMK 槽（唯一入口：派生/验证/改钥成功后调用）
pub(super) fn store_gmk(gmk: zeroize::Zeroizing<[u8; 32]>) {
    GMK.with(|g| *g.borrow_mut() = Some(gmk));
}

thread_local! {
    /// GMK 内存持有（Zeroizing 保证清零）
    pub(crate) static GMK: RefCell<Option<zeroize::Zeroizing<[u8; 32]>>> = const { RefCell::new(None) };
}
