/**
 * photo-album/usePhotoDelete.ts — 拾光模块删除层 composable
 *
 * 职责：管理批量删除与选择模式。
 *
 * 设计要点：
 * - 接收 usePhotoData 返回值中的 photos/isTauri + 全局 Toast 中心的 showError/showToast（依赖注入）
 * - onView 由外部传入（来自 usePhotoViewer），选择模式下拦截点击改为切换选中
 * - showToast 由外部传入，用于删除成功提示
 * - 删除一律走 metaId（非 meta），重启后占位项也能正确级联删除 verthys 记录
 * - onDeleteBtn（右上角按钮）仅切换选择模式，不承担删除动作；
 *   真实删除由选择栏 onDeleteSelected 拉起二次确认，confirmDelete → executeBatchDelete 执行
 * - 批量删除合并为单次 flush（deleteAndPersistBatch + persistVerthys）
 * - shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
 */
import { ref, computed, type ShallowRef } from "vue";
import { verthysForgetImportKeys, verthysGcOrphanChunks } from "../../lib/verthys";
import {
  persistVerthysDetailed, deleteAndPersistBatch, setModuleCache,
  invalidateSummaryRecord, invalidateFullRecord, invalidateScannedRecord,
} from "../../lib/keyManager";
import { removeShallowItems, replaceShallowArray } from "../../utils/shallow-array";
import type { PhotoEntry } from "./types";
import { revokeThumbUrl, sortByMetaId, toPhotoCacheEntries } from "./utils";

/** usePhotoDelete 参数接口 */
export interface UsePhotoDeleteParams {
  /** 照片列表（shallowRef，避免深度代理） */
  photos: ShallowRef<PhotoEntry[]>;
  /** 是否处于 Tauri 环境 */
  isTauri: boolean;
  /** 打开查看器回调（非选择模式下点击照片时调用，来自 usePhotoViewer） */
  onView: (ph: PhotoEntry) => void;
  /** 显示错误提示（来自全局 Toast 中心） */
  showError: (msg: string) => void;
  /** 成功提示回调（来自全局 Toast 中心，用于删除完成提示） */
  showToast: (msg: string) => void;
}

export function usePhotoDelete(params: UsePhotoDeleteParams) {
  const { photos, isTauri, onView, showError, showToast } = params;

  /* ===== 删除进行中（防重入 + 相册忙碌态） ===== */
  const deleting = ref(false);

  /* ===== 选择删除模式 ===== */
  const selectMode = ref(false);
  const selectedPhotoIds = ref(new Set<number>());

  /* ===== 删除二次确认（复用 ConfirmDelete 弹窗） ===== */
  const showDeleteConfirm = ref(false);

  /** 是否全选 */
  const allSelected = computed(() => {
    return photos.value.length > 0 && selectedPhotoIds.value.size === photos.value.length;
  });

  /** 全选 / 取消全选 */
  const toggleSelectAll = () => {
    if (allSelected.value) {
      selectedPhotoIds.value = new Set();
    } else {
      selectedPhotoIds.value = new Set(photos.value.map(p => p.id));
    }
  };

  /** 取消选择模式 */
  const cancelSelectMode = () => {
    selectMode.value = false;
    selectedPhotoIds.value = new Set();
  };

  /** 右上角删除按钮：仅切换选择模式，不承担任何删除动作
   *
   * 职责拆分：本按钮只负责调出/收起选择模式与下方删除操作栏；
   * 真正的删除流程由选择栏「删除选中」按钮（onDeleteSelected）拉起确认后执行。
   */
  const onDeleteBtn = () => {
    if (deleting.value) return;
    // 感知：无照片时不进入框选模式，直接给出响应提示
    //    避免空状态下点击删除按钮无反馈，用户无法感知
    if (photos.value.length === 0) {
      showError("暂无照片可删除");
      return;
    }
    if (!selectMode.value) {
      // 进入选择模式
      selectMode.value = true;
      selectedPhotoIds.value = new Set();
      return;
    }
    // 已在选择模式：退出并清空选中（与「取消」按钮行为一致）
    cancelSelectMode();
  };

  /** 选择栏「删除选中」按钮：拉起删除确认窗口（不直接删除）
   *
   * 误触防御：批量删除不可撤销，必须经 ConfirmDelete 二次确认后
   * 由 confirmDelete → executeBatchDelete 执行。
   */
  const onDeleteSelected = () => {
    if (deleting.value) return;
    // 空选时按钮处于禁用态，此处为事件兜底
    if (selectedPhotoIds.value.size === 0) return;
    showDeleteConfirm.value = true;
  };

  /** 取消删除确认：仅关闭确认窗口，保持选择模式与已选状态不变 */
  const cancelDeleteConfirm = () => {
    showDeleteConfirm.value = false;
  };

  /** 确认删除：关闭确认窗口后执行批量删除 */
  const confirmDelete = async () => {
    if (deleting.value) return;
    showDeleteConfirm.value = false;
    await executeBatchDelete();
  };

  /**
   * 按 metaId 批量删除（选择删除与损坏清理共用）。
   *
   * 响应链路：
   *   1. 同步启动删除（deleteAndPersistBatch 同步登记 pendingDeletionIds 与
   *      快照，杜绝扫描窗口把待删记录回填进缓存）；
   *   2. 立即从相册移除卡片并同步模块缓存——用户操作下一帧即得到响应；
   *   3. 后台等待单次批量删除 IPC（后端按台账展开外置块，前端不逐条解密
   *      meta）+ 落盘确认 + 续传幂等锁释放；
   *   4. 删除未发生（false/异常）时恢复卡片与缓存，绝不出现「界面已删、
   *      磁盘仍在」的隐形丢失。
   *
   * 级联权威来源：外置块台账（chunk id → owner meta id）。前端只提交
   * metaId，后端单次事务删除 meta + 其全部外置块（含瘦身缩略图/块集）。
   *
   * @returns true=删除已提交；false=删除未发生（卡片与缓存已恢复）
   */
  const deleteByMetaIds = async (
    metaIdsInput: number[],
    successMessage: (count: number) => string,
  ): Promise<boolean> => {
    if (deleting.value) return false;
    const metaIds = [...new Set(
      metaIdsInput.filter((id): id is number => typeof id === "number" && id > 0),
    )];
    if (metaIds.length === 0) return true;

    const metaIdSet = new Set(metaIds);
    const photosToRemove = photos.value.filter(
      (p) => typeof p.metaId === "number" && metaIdSet.has(p.metaId),
    );

    deleting.value = true;

    // 先启动删除再移除卡片：异步函数同步段会立即登记待删过滤集合与快照
    const deletePromise: Promise<boolean> = isTauri && metaIds.length > 0
      ? deleteAndPersistBatch(metaIds)
      : Promise.resolve(true);

    // 即刻响应：卡片立即消失，缓存同步为当前视图
    removeShallowItems(photos, p => typeof p.metaId === "number" && metaIdSet.has(p.metaId));
    setModuleCache("photos", toPhotoCacheEntries(photos.value));

    try {
      let deleted = false;
      try {
        deleted = await deletePromise;
      } catch (e) {
        console.warn("[deleteByMetaIds] deleteAndPersistBatch 失败", e);
      }
      if (!deleted) {
        // 删除未发生：恢复卡片与缓存（保持记录 ID 升序）
        replaceShallowArray(photos, sortByMetaId([...photos.value, ...photosToRemove]));
        setModuleCache("photos", toPhotoCacheEntries(photos.value));
        showError("删除未生效（数据仍保留），请重试");
        return false;
      }

      // 删除已在 worker 单事务内提交并落盘；此处确认缓存落盘并释放续传锁。
      let outcome: Awaited<ReturnType<typeof persistVerthysDetailed>> = { kind: "ok" };
      if (isTauri && metaIds.length > 0) {
        try {
          outcome = await persistVerthysDetailed();
        } catch (e) {
          console.error("[deleteByMetaIds] persistVerthysDetailed 异常", e);
          outcome = { kind: "not_persisted", reason: String(e) };
        }

        // 释放续传幂等锁：优先使用已解密 meta 携带的条目键，并附带记录 ID
        // 由后端按 WAL committed 映射反查（历史 WAL 缺 ID 时两侧互补，
        // meta 未解密/不可解密时也不会阻塞删除）。
        const forgetKeys = photosToRemove
          .map((ph) => ph.meta?.entryKey)
          .filter((key): key is string => typeof key === "string" && key.length > 0);
        try {
          await verthysForgetImportKeys(forgetKeys, metaIds);
        } catch (e) {
          console.warn("[deleteByMetaIds] 续传幂等锁释放失败（不影响删除结果）", e);
        }

        // 失效三层缓存（摘要 + 全量 + 扫描回退），杜绝删除复活
        for (const rid of metaIds) {
          invalidateSummaryRecord(rid);
          invalidateFullRecord(rid);
          invalidateScannedRecord(rid);
        }

        // 孤儿块 GC 为后台收尾：不阻塞删除完成反馈（失败仅推迟到下次时机）
        verthysGcOrphanChunks()
          .then((collected) => {
            if (collected > 0) {
              console.info(`[deleteByMetaIds] 孤儿块 GC 清理 ${collected} 条残留块记录`);
            }
          })
          .catch((e) => console.warn("[deleteByMetaIds] 孤儿块 GC 失败（可下次再触发）", e));
      }

      // 删除成功后才回收缩略图 Blob URL；失败恢复时 URL 仍然有效
      for (const ph of photosToRemove) {
        if (ph.blobUrl) URL.revokeObjectURL(ph.blobUrl);
        if (ph.thumb) revokeThumbUrl(ph.thumb);
      }

      if (outcome.kind === "not_persisted") {
        showError("删除已执行但落盘校验失败，重启后照片可能恢复。请重试。");
      } else if (outcome.kind === "partial_persisted") {
        showToast(`${successMessage(metaIds.length)}（落盘校验警告）：${outcome.reason}`);
      } else {
        showToast(successMessage(metaIds.length));
      }
      return true;
    } finally {
      deleting.value = false;
    }
  };

  /** 执行批量删除（不含确认交互，由 confirmDelete 调用） */
  const executeBatchDelete = async () => {
    if (deleting.value) return;
    const photoIds = Array.from(selectedPhotoIds.value);
    if (photoIds.length === 0) return;
    // 集合命中代替 includes：万张相册全选时避免 O(n·m)
    const idSet = new Set(photoIds);
    const metaIds = photos.value
      .filter((p) => idSet.has(p.id))
      .map((p) => p.metaId)
      .filter((id): id is number => typeof id === "number" && id > 0);

    selectedPhotoIds.value = new Set();
    selectMode.value = false;

    await deleteByMetaIds(metaIds, (count) => `已删除 ${count} 张照片`);
  };

  /**
   * 清理确定损坏（内容层认证失败）的照片记录。
   *
   * 仅接受调用方经扫描确认的 metaId；删除走与手动删除相同的台账级联、
   * 落盘校验与孤儿块回收链路。调用方必须先取得用户显式确认。
   */
  const cleanupDamaged = async (metaIds: number[]): Promise<boolean> =>
    deleteByMetaIds(metaIds, (count) => `已清理 ${count} 条无法解密的记录`);

  /** 照片点击：选择模式下切换选中，非选择模式下打开查看器 */
  const onPhotoClick = (ph: PhotoEntry) => {
    if (selectMode.value) {
      const s = new Set(selectedPhotoIds.value);
      if (s.has(ph.id)) s.delete(ph.id);
      else s.add(ph.id);
      selectedPhotoIds.value = s;
    } else {
      onView(ph);
    }
  };

  return {
    selectMode,
    selectedPhotoIds,
    allSelected,
    deleting,
    toggleSelectAll,
    cancelSelectMode,
    onDeleteBtn,
    onDeleteSelected,
    showDeleteConfirm,
    confirmDelete,
    cancelDeleteConfirm,
    onPhotoClick,
    /** 损坏清理：按扫描确认的 metaId 删除（不可逆，调用方先取用户确认） */
    cleanupDamaged,
  };
}
