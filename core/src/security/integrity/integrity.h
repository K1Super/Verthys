/*
 * integrity.h — 惰性关键段完整性校验 + 分散式校验锚点（内部模块，不导出）
 *
 * 用户需求（一.1 关键段完整性校验）：
 *   - 惰性关键段自校验：仅在程序入口校验核心解密引擎模块（DLL/SO）及主 EXE
 *     头部关键区段（约前 1MB）。其余 UI/图标/语言包不参与启动校验，达成秒开。
 *   - 分散式校验锚点：将剩余完整性校验逻辑打散，埋入"打开设置页""切换目录树"
 *     "导出文件"等高频功能函数入口。攻击者无法通过单点内存补丁绕过。
 *   - 资源文件加密：UI 布局、配置模板加密打包存储。
 *
 * 技术方案：
 *   - 启动校验：BLAKE3 哈希计算 DLL .text 段 + EXE 前 1MB，与编译期预置值比对
 *   - 分散锚点：每个锚点校验不同区段（.text 子区间 / .rdata / PE 头），
 *     避免攻击者通过单点 patch 绕过全部校验
 *   - 校验失败不弹出提示，静默进入应急流程（见 emergency.h）
 */
#ifndef VERTHYS_INTEGRITY_H
#define VERTHYS_INTEGRITY_H

#include <stdint.h>
#include <stddef.h>

/* 校验锚点 ID（分散式校验点，每个对应不同功能入口） */
typedef enum {
    ANCHOR_STARTUP        = 0,  /* 程序入口：DLL .text + EXE 头部1MB */
    ANCHOR_OPEN_SETTINGS  = 1,  /* 打开设置页：DLL .rdata 段 */
    ANCHOR_SWITCH_TREE    = 2,  /* 切换目录树：DLL .text 后半段 */
    ANCHOR_EXPORT_FILE    = 3,  /* 导出文件：EXE PE 头 + 入口表 */
    ANCHOR_IMPORT_FILE    = 4,  /* 导入文件：DLL 导出表 */
    ANCHOR_CHANGE_PASSWORD= 5,  /* 修改密码：DLL .text 前半段 */
    ANCHOR_UNLOCK         = 6,  /* 解锁操作：EXE .text 段抽样 */
    ANCHOR_COUNT
} IntegrityAnchor;

/*
 * 初始化完整性校验模块。
 * 计算并缓存各锚点的基准哈希值（首次调用时）。
 * 返回 0 成功，非 0 失败。
 */
int integrity_init(void);

/*
 * 执行指定锚点的完整性校验。
 *   anchor: 校验锚点 ID
 * 返回 0=通过，非 0=校验失败（检测到篡改）。
 * 失败时应触发应急流程，不直接退出。
 */
int integrity_check_anchor(IntegrityAnchor anchor);

/*
 * 启动时惰性校验（仅校验 DLL .text + EXE 头部1MB）。
 * 等价于 integrity_check_anchor(ANCHOR_STARTUP)，但独立暴露以便入口点调用。
 */
int integrity_check_startup(void);

/*
 * 设置预置哈希基准值（post-build 工具调用）。
 *   anchor: 锚点 ID
 *   hash:   32 字节哈希值（BLAKE3 或 SHA-256）
 * 全零 = 未配置 = 跳过校验。
 */
void integrity_set_baseline(IntegrityAnchor anchor, const uint8_t hash[32]);

/* ===================================================================== *
 * ★ 方案 §6.3：构建期签名 + 一次性验签（.vsec 机制）                    *
 * ===================================================================== */

/*
 * 启动时一次性验签（Verthys_Unlock 入口调用）。
 *
 * 机制：构建脚本（build_core.release.ps1）在链接完成后计算 .text 与
 * .rdata 节的文件内容 HMAC-SHA256（固定域密钥，同时编译进 DLL 与脚本），
 * 写入 DLL 新增只读节 .vsec。运行时从磁盘读取自身 PE 文件，重算两节
 * HMAC 并与 .vsec 基准做常量时间比对。
 *
 * 设计要点：
 *   - 以【文件内容】为校验对象（而非内存映像）：与构建期签名的字节源
 *     完全一致，天然免疫 ASLR 基址重定位，杜绝误报（内存中含重定位
 *     写入的绝对地址，节内存哈希跨启动不稳定——见审计报告 §4.3(6)）；
 *   - .vsec 全零 = 未配置（开发构建）→ 跳过校验返回 0；
 *   - 校验失败 = 分发二进制被篡改（高置信度）→ KILL 级
 *     EMERG_SIG_INTEGRITY_FAIL 上报，并返回 VERTHYS_ERR_CORRUPT。
 *
 * 返回 0 = 通过（或未配置）；非 0 = 验签失败（VERTHYS_ERR_CORRUPT）。
 */
__declspec(noinline) int integrity_verify_startup(void);

#endif /* VERTHYS_INTEGRITY_H */
