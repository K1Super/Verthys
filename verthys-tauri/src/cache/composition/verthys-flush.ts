/*
 * cache/composition/verthys-flush.ts — Verthys 统一冲刷队列服务（对外 API 绑定层）
 *
 * 重构落地：
 *   全部冲刷队列逻辑已抽取到 cache/domain/verthys-flush-service.ts（VerthysFlushService
 *   领域类），本文件仅做服务实例化与对外 API 绑定，签名与旧版逐一对应，
 *   所有消费方（global-verthys.ts / module-auth.ts / keyManager.ts / verthys-cache.ts）
 *   无需任何改动。
 *
 * 兼容性说明：
 *   旧版同时导出 pendingDeletionIds / committedDeletionIds 两个活动 Set
 *   （verthys-cache.ts 引用作为扫描过滤的单一权威源）。Service 类将其保留为
 *   私有状态并通过 getter 暴露同一实例，本层继续导出——集合内容始终原地
 *   变更（add/delete/clear），引用恒定，live binding 语义与旧版一致。
 *
 * 对外 API ：
 *   持久化：persistVerthys / deleteAndPersist / deleteAndPersistBatch
 *   调度：  enqueueFlush / flushVerthysNow / flushQueueStatus / waitForFlush
 *           scheduleBackgroundFlush / cancelDebouncedFlush
 *   生命周期：resetFlushChain / clearAllCacheTimers / isCacheTimersCancelled
 *   删除过滤：isPendingDeletion / clearPendingDeletionIds /
 *             pendingDeletionIds / committedDeletionIds
 *   状态查询：isFlushing / isCacheDirty / setCacheDirty / pendingFlushWorkRef
 *   快照注入：setSnapshotProvider
 */
import { VerthysFlushService } from "../domain/verthys-flush-service";
import { getCurrentVerthysPath } from "../../state/key_state";

const service = new VerthysFlushService(() => getCurrentVerthysPath());

export const setSnapshotProvider = service.setSnapshotProvider.bind(service);
export const persistVerthys = service.persistVerthys.bind(service);
export const deleteAndPersist = service.deleteAndPersist.bind(service);
export const deleteAndPersistBatch = service.deleteAndPersistBatch.bind(service);
export const waitForFlush = service.waitForFlush.bind(service);
export const isFlushing = service.isFlushing.bind(service);
export const cancelDebouncedFlush = service.cancelDebouncedFlush.bind(service);
export const resetFlushChain = service.resetFlushChain.bind(service);
export const clearAllCacheTimers = service.clearAllCacheTimers.bind(service);
export const scheduleBackgroundFlush = service.scheduleBackgroundFlush.bind(service);
export const isPendingDeletion = service.isPendingDeletion.bind(service);
export const isCacheDirty = service.isCacheDirty.bind(service);
export const clearPendingDeletionIds = service.clearPendingDeletionIds.bind(service);
export const setCacheDirty = service.setCacheDirty.bind(service);
export const pendingFlushWorkRef = service.pendingFlushWorkRef;
export const enqueueFlush = service.enqueueFlush.bind(service);
export const flushVerthysNow = service.flushVerthysNow.bind(service);
export const flushQueueStatus = service.flushQueueStatus.bind(service);
export const isCacheTimersCancelled = service.isCacheTimersCancelled.bind(service);

/* 共享删除过滤集合（单一权威源，兼容性说明附于文件头）：
 *   VerthysCacheDomain 通过 verthys-cache.ts 注入同一实例，
 *   确保冲刷队列与缓存扫描的过滤视图完全一致。 */
export const pendingDeletionIds = service.pendingDeletionIds;
export const committedDeletionIds = service.committedDeletionIds;
