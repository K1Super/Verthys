/* 全局密钥记录 I/O：抽象、Worker 实现、分页枚举与有效记录解析 */

use super::gmk_state::{
    CODE_NOTFOUND, CODE_OK, CODE_RESOURCE_LIMIT, GLOBAL_KEY_MAX_CANDIDATES,
    GLOBAL_KEY_NAME, GLOBAL_KEY_PAGE_SIZE, GLOBAL_KEY_RECORD_LEN, TYPE_GLOBAL_KEY,
};
use crate::runtime::worker::Worker;

/// 全局密钥记录 I/O 抽象：真实实现走 Worker FFI，测试用内存 fake。
///
/// 把记录读写与 GMK 编排分离，使"旧钥错误 / 写失败 / 读回不一致 /
/// 删旧失败 / 成功换槽"等分支可在无 DLL 环境下被真实覆盖。
pub(super) trait GmkRecordIo {
    fn list_ids_page(
        &self,
        rtype: u8,
        after_id: u64,
        max_count: u64,
    ) -> Result<(Vec<u64>, bool), u32>;
    fn get_record(&self, id: u64) -> Result<(u32, String, Vec<u8>), u32>;
    fn add_record(&self, rtype: u8, name: &str, data: &[u8]) -> Result<u64, u32>;
    /// 原子替换（API 0x0017）；未导出时返回 VERTHYS_SYMBOL_UNSUPPORTED
    fn replace_record(
        &self,
        old_id: u64,
        rtype: u8,
        name: &str,
        data: &[u8],
    ) -> Result<u64, u32>;
    fn delete_record(&self, id: u64) -> Result<(), u32>;
}

pub(super) struct WorkerRecordIo<'a>(pub(super) &'a Worker);

impl GmkRecordIo for WorkerRecordIo<'_> {
    fn list_ids_page(
        &self,
        rtype: u8,
        after_id: u64,
        max_count: u64,
    ) -> Result<(Vec<u64>, bool), u32> {
        let mut ids = vec![0u64; max_count as usize];
        let mut count = 0u64;
        let mut exhausted = 0u8;
        let rc = self.0.call_list_ids_by_type(
            rtype,
            after_id,
            max_count,
            &mut ids,
            &mut count,
            &mut exhausted,
        );
        if rc != CODE_OK {
            return Err(rc);
        }
        ids.truncate(count as usize);
        Ok((ids, exhausted != 0))
    }

    fn get_record(&self, id: u64) -> Result<(u32, String, Vec<u8>), u32> {
        self.0.call_get_record(id)
    }

    fn add_record(&self, rtype: u8, name: &str, data: &[u8]) -> Result<u64, u32> {
        self.0.call_add_record(rtype as u32, name, data)
    }

    fn replace_record(
        &self,
        old_id: u64,
        rtype: u8,
        name: &str,
        data: &[u8],
    ) -> Result<u64, u32> {
        self.0.call_replace_record(old_id, rtype as u32, name, data)
    }

    fn delete_record(&self, id: u64) -> Result<(), u32> {
        let rc = self.0.call_delete_record(id);
        if rc == CODE_OK {
            Ok(())
        } else {
            Err(rc)
        }
    }
}

/// 分页枚举 type 索引中的全部 ID（升序；跳过墓碑）
fn list_all_global_key_ids(io: &dyn GmkRecordIo) -> Result<Vec<u64>, u32> {
    let mut all = Vec::new();
    let mut after = 0u64;
    loop {
        let (page, exhausted) = io.list_ids_page(TYPE_GLOBAL_KEY, after, GLOBAL_KEY_PAGE_SIZE)?;
        if page.is_empty() {
            break;
        }
        if let Some(&last) = page.last() {
            after = last;
        }
        all.extend(page);
        if all.len() > GLOBAL_KEY_MAX_CANDIDATES {
            return Err(CODE_RESOURCE_LIMIT);
        }
        if exhausted {
            break;
        }
    }
    Ok(all)
}

/// 解析全部有效全局密钥记录（type/name/长度三要素），按 id 升序返回
pub(super) fn resolve_valid_global_key_records(
    io: &dyn GmkRecordIo,
) -> Result<Vec<(u64, Vec<u8>)>, u32> {
    let ids = list_all_global_key_ids(io)?;
    let mut out = Vec::new();
    for id in ids {
        match io.get_record(id) {
            Ok((rtype, name, data))
                if rtype == TYPE_GLOBAL_KEY as u32
                    && name == GLOBAL_KEY_NAME
                    && data.len() == GLOBAL_KEY_RECORD_LEN =>
            {
                out.push((id, data));
            }
            Ok(_) => {}
            Err(CODE_NOTFOUND) => {}
            Err(rc) => return Err(rc),
        }
    }
    out.sort_by_key(|(id, _)| *id);
    Ok(out)
}
