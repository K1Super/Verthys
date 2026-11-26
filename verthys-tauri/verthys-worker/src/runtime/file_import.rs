/*
 * file_import.rs — 清藏（文件保险箱）原生导入 job
 *
 * 职责：worker 内完成清藏导入的全部数据面工作——流式读文件、BLAKE3、
 * 文件级口令 KDF、逐块 AES-GCM、模块外层封装、密文暂存与 meta 序列化；
 * 宿主只按引用提交块并写入 meta，前端不接触任何块字节。
 *
 * 与拾光导入的边界：两者共用单写者会话、暂存区与孤儿回收，但 job、
 * 命名空间与记录角色完全独立；本模块不得引入照片解码/缩略图依赖。
 *
 * 兼容约束（读取侧按既有 meta 字段分流，不得变更）：
 *   - 加密条目：每文件一次 PBKDF2（旧管线每块一次），盐与迭代次数随
 *     meta 落盘；块布局为 分片(域标签 v2_chunk ‖ iv ‖ 密文+tag)。
 *   - 明文条目：块载荷即明文字节，与旧管线逐字节一致。
 *   - 文件哈希 = BLAKE3(明文 ‖ [格式版本, 加密形态])，去重键不含内容。
 *
 * 状态只驻留内存；已写入的块由宿主会话映射与孤儿 GC 结算。
 *
 * 子模块：job（状态/常量/回收）、handlers（五个命令）、pipeline（文件推进、
 * 键/哈希、meta 与响应装配）、tests。
 */

mod handlers;
mod job;
mod pipeline;

#[cfg(test)]
mod tests;

pub(crate) use handlers::{
    handle_begin, handle_cancel, handle_end, handle_finish, handle_next,
};
