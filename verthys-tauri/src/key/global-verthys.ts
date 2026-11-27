/*
 * key/global-verthys.ts — 全局加密库与 GMK 管理层（统一导出入口）
 *
 * 职责：
 *   1. 加密库初始化（checkInitStatus / initCreate / initUnlock / initAndUnlock）
 *   2. 全局根密钥 CRUD（initGlobalKey / changeGlobalKey / verifyGlobalKey / verifyGlobalKeyWithBruteForce）
 *   3. 设备绑定（bindDevice / verifyDeviceBinding / getDeviceFingerprintShort）
 *   4. .bin 文件读取（readBinFile）
 *
 * 实现按域拆分在 key/global/ 下，本文件只做重导出。
 */

// 再导出 Worker 预启动接口，供 SecurityCenter 等上层组件使用
export { preloadWorker, invalidateWorkerPreload } from "../lib/verthys";

export * from "./global/status";
export * from "./global/create";
export * from "./global/unlock";
export * from "./global/key_ops";
export * from "./global/verify";
export * from "./global/device";
