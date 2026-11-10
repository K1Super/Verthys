/*
 * integrity.h — 程序镜像完整性验签（.vsec）（内部模块，不导出）
 *
 * 构建期在 DLL 只读节 .vsec 写入 .text/.rdata/.rhat 的 HMAC 基准；
 * 运行时从磁盘读取自身 PE 文件重算并比对，失败即拒绝解锁。
 */
#ifndef VERTHYS_INTEGRITY_H
#define VERTHYS_INTEGRITY_H

#include <stdint.h>
#include <stddef.h>

/*
 * 自身文件验签缓存白盒（仅 tests 使用）：
 *   - integrity_verify_recompute_count：累计冷路径重算次数——
 *     缓存回放时计数不动，指纹失效时必增（确定的缓存生效证据）；
 *   - integrity_verify_cache_reset：清空缓存条目，强制下一轮走冷路径。
 */
long integrity_verify_recompute_count(void);
void integrity_verify_cache_reset(void);

/* ===================================================================== *
 * 构建期签名 + 一次性验签（.vsec 机制）
 * ===================================================================== */

/*
 * 启动时一次性验签（Verthys_V4Unlock 入口调用）。
 *
 * 机制：构建脚本在链接完成后计算 .text 与
 * .rdata 节的文件内容 HMAC-SHA256（固定域密钥，同时编译进 DLL 与脚本），
 * 写入 DLL 新增只读节 .vsec。运行时从磁盘读取自身 PE 文件，重算两节
 * HMAC 并与 .vsec 基准做常量时间比对。
 *
 * 设计要点：
 *   - 以【文件内容】为校验对象（而非内存映像）：与构建期签名的字节源
 *     完全一致，天然免疫 ASLR 基址重定位，杜绝误报（内存中含重定位
 *     写入的绝对地址，节内存哈希跨启动不稳定）；
 *   - 进程内指纹缓存（解锁热路径）：以自身文件句柄的元数据指纹
 *     （卷序列号 + 文件索引 + 大小 + 最后写入时间）为键缓存验签结论，
 *     指纹不变 → 回放结论（零节 I/O）；指纹变化（自更新/篡改）→ 强制
 *     重算。缓存条目由模块级单飞锁保护，指纹与验签读取同一文件句柄
 *     （无路径替换竞态）；
 *   - .vsec 全零 = 未配置（开发构建）→ 跳过校验返回 0；
 *   - 校验失败 = 分发二进制被篡改（高置信度）→ KILL 级
 *     EMERG_SIG_INTEGRITY_FAIL 上报，并返回 VERTHYS_ERR_CORRUPT。
 *
 * 返回 0 = 通过（或未配置）；非 0 = 验签失败（VERTHYS_ERR_CORRUPT）。
 */
__declspec(noinline) int integrity_verify_startup(void);

#endif /* VERTHYS_INTEGRITY_H */
