/**
 * photo-album/usePhotoDelete.ts — 拾光模块删除层 composable
 *
 * 职责：管理单张删除、批量删除、选择模式。
 * 从原 PhotoAlbum.vue 提取，保持 100% 功能不变。
 *
 * 设计要点：
 * - 接收 usePhotoData 返回值中的 photos/isTauri + usePhotoToast 的 showError/showToast（依赖注入）
 * - onView 由外部传入（来自 usePhotoViewer），选择模式下拦截点击改为切换选中
 * - showToast 由外部传入，用于删除成功提示
 * - onDelete 基于 metaId 判断（非 meta），重启后占位项也能正确删除 verthys 记录
 * - onDeleteBtn 批量删除合并为单次 flush（deleteAndPersistBatch + persistVerthys）
 * - shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
 */
import { ref, computed, type ShallowRef } from "vue";
import { verthysDeleteRecord } from "../../lib/verthys";
import {
  persistVerthys, deleteAndPersistBatch, setModuleCache,
  invalidateSummaryRecord, invalidateFullRecord, invalidateScannedRecord,
} from "../../lib/keyManager";
import { removeShallowItems } from "../../utils/shallow-array";
import type { PhotoEntry } from "./types";

/** usePhotoDelete 参数接口 */
export interface UsePhotoDeleteParams {
  /** 照片列表（shallowRef，避免深度代理） */
  photos: ShallowRef<PhotoEntry[]>;
  /** 是否处于 Tauri 环境 */
  isTauri: boolean;
  /** 打开查看器回调（非选择模式下点击照片时调用，来自 usePhotoViewer） */
  onView: (ph: PhotoEntry) => void;
  /** 显示错误提示（来自 usePhotoToast，统一 Toast 中心） */
  showError: (msg: string) => void;
  /** 成功提示回调（来自 usePhotoToast，用于删除完成提示） */
  showToast: (msg: string) => void;
}

export function usePhotoDelete(params: UsePhotoDeleteParams) {
  const { photos, isTauri, onView, showError, showToast } = params;

  /* ===== 删除 ===== */
  const onDelete = async (id: number) => {
    const ph = photos.value.find(p => p.id === id);
    // ★ 企业级根治：删除判断基于 metaId（始终存在）而非 meta（可能未解密）
    //    旧实现 if (ph?.meta && isTauri) 在重启后 meta 未解密时跳过整个 verthys 删除，
    //    导致：UI 移除了照片，但 verthys 记录仍在磁盘 → 重启后"删除的照片复活"。
    //    修复：Tauri 模式下只要有 metaId 就执行 verthys 删除 + 缓存失效；
    //    旧格式 chunkIds 清理单独检查 ph.meta（仅旧格式有 chunkIds）。
    if (isTauri && ph?.metaId) {
      // 删除 meta 记录（新格式的 chunk 数据已内联在 meta 中，删 meta 即可彻底清除）
      try { await verthysDeleteRecord(ph.metaId); } catch (e) {
        if (e instanceof Error && e.message === "VERTHYS_WRITE_BLOCKED") {
          showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
          return;
        }
        /* 其他错误静默 */
      }
      // ★ Phase 2E：同时失效两层缓存（摘要 + 全量），杜绝删除复活
      //    invalidateSummaryRecord：从 summaryCache + 类型索引移除（列表不再显示）
      //    invalidateFullRecord：从 fullRecordCache 安全覆写移除（dataB64 清零）
      //    同时保留旧 invalidateScannedRecord 兼容（recordScanCache 回退路径）
      invalidateSummaryRecord(ph.metaId);
      invalidateFullRecord(ph.metaId);
      invalidateScannedRecord(ph.metaId);
      // 旧格式兼容：如有单独的 chunk 记录，一并删除（仅旧格式 meta 有 chunkIds）
      if (ph.meta?.chunkIds && ph.meta.chunkIds.length > 0) {
        for (const cid of ph.meta.chunkIds) {
          try { await verthysDeleteRecord(cid); } catch (e) {
            if (e instanceof Error && e.message === "VERTHYS_WRITE_BLOCKED") {
              showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
              return;
            }
            /* 其他错误静默 */
          }
          // ★ Phase 2E：chunk 记录同样失效两层缓存
          invalidateSummaryRecord(cid);
          invalidateFullRecord(cid);
          invalidateScannedRecord(cid);
        }
      }
    }
    // 浏览器模式：释放 Blob URL
    if (ph?.blobUrl) URL.revokeObjectURL(ph.blobUrl);
    // ★ 项2：shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
    removeShallowItems(photos, p => p.id === id);
    // 更新缓存
    setModuleCache("photos", photos.value);
    // ★ 企业级根治：持久化删除操作到磁盘 + 返回值检查
    //    旧实现仅 try/catch 吞掉异常，忽略 persistVerthys 返回的 false（flush 失败），
    //    导致删除操作未落盘 → 重启后"删除的照片复活"。
    //    修复：检查返回值，失败时提示用户。
    if (isTauri) {
      let persistOk = false;
      try {
        persistOk = await persistVerthys();
      } catch (e) {
        console.error("[onDelete] persistVerthys 异常", e);
      }
      if (!persistOk) {
        showError("删除操作持久化失败，重启后照片可能恢复。请重试或重新删除。");
      }
    }
  };

  /* ===== 选择删除模式 ===== */
  const selectMode = ref(false);
  const selectedPhotoIds = ref(new Set<number>());

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

  /** 顶部删除按钮：切换选择模式 / 确认删除选中
   *
   * ★ 落实 upgrade.md "批量删除必须合并为单次 flush"：
   *   旧实现循环逐张 onDelete(id) → 每张 verthysDeleteRecord + persistVerthys = 2N 次 IPC + N 次事务提交（IO 风暴）
   *   新实现收集全部 metaId + chunkIds 一次性 deleteAndPersistBatch → 1 次 IPC + 1 次事务提交（恒定 IO）
   *   无论删除多少张照片，磁盘写入量恒定，仅与索引区大小相关。
   */
  const onDeleteBtn = async () => {
    // ★ 企业级感知：无照片时不进入框选模式，直接给出响应提示
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
    // 已在选择模式
    if (selectedPhotoIds.value.size === 0) {
      // 无选中，退出选择模式
      selectMode.value = false;
      return;
    }

    // ★ 批量删除：收集全部待删除照片 + 对应记录 ID（metaId + 旧格式 chunkIds）
    const ids = Array.from(selectedPhotoIds.value);
    const photosToRemove = photos.value.filter(p => ids.includes(p.id));
    const allRecordIds: number[] = [];
    for (const ph of photosToRemove) {
      if (ph.metaId) allRecordIds.push(ph.metaId);
      // 旧格式兼容：如有单独的 chunk 记录，一并加入批量删除
      if (ph.meta?.chunkIds && ph.meta.chunkIds.length > 0) {
        for (const cid of ph.meta.chunkIds) allRecordIds.push(cid);
      }
    }

    if (isTauri && allRecordIds.length > 0) {
      // ★ 单次 IPC + 单次事务提交（落实 upgrade.md 批量删除合并单次 flush）
      //    deleteAndPersistBatch 内部：全部 ID 加入 pendingDeletionIds →
      //    verthysDeleteRecords(ids) 一次 IPC → worker 单次 vtxn_commit →
      //    防抖调度单次 flush（300ms 窗口）
      try {
        await deleteAndPersistBatch(allRecordIds);
        // ★ 企业级根治：await persistVerthys 强制立即落盘（根治删除后复活）+ 返回值检查
        //
        // 原缺陷：deleteAndPersistBatch 仅防抖调度 flush（300ms），不等待落盘
        //   即返回。应用退出 → 防抖 flush 未执行 → 磁盘仍含已删照片 → "删除后复活"。
        //
        // 修复：await persistVerthys 取消防抖定时器，立即 doFlush 落盘。
        //   persistVerthys 内部 cancelDebouncedFlush + flushChain.then(doFlush)，
        //   确保磁盘写入完成才返回。UI 已同步移除（无缝删除），await 不阻塞渲染。
        //   ★ 新增：检查返回值，失败时提示用户删除可能未落盘。
        const persistOk = await persistVerthys();
        if (!persistOk) {
          showError("删除操作持久化失败，重启后照片可能恢复。请重试或重新删除。");
        }
      } catch (e) {
        if (e instanceof Error && e.message === "VERTHYS_WRITE_BLOCKED") {
          showError("当前加密库格式需要升级，暂无法写入新数据，请重新打开应用重试升级或导出已有数据");
          return;
        }
        console.warn("[onDeleteBtn] deleteAndPersistBatch 失败", e);
        showError("删除失败，请重试");
      }
      // ★ Phase 2E：失效两层缓存（摘要 + 全量 + 扫描回退），杜绝删除复活
      for (const rid of allRecordIds) {
        invalidateSummaryRecord(rid);
        invalidateFullRecord(rid);
        invalidateScannedRecord(rid);
      }
    }

    // ★ 浏览器模式：释放 Blob URL；统一回收（含 Tauri 模式）
    for (const ph of photosToRemove) {
      if (ph.blobUrl) URL.revokeObjectURL(ph.blobUrl);
    }
    // ★ 删除按钮完毕的瞬间移除对应内容，消除内容实际删除之间的空白间隔，做到无缝衔接
    const removedIdSet = new Set(ids);
    // ★ 项2：shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
    removeShallowItems(photos, p => removedIdSet.has(p.id));
    // 更新缓存
    setModuleCache("photos", photos.value);
    // ★ 企业级根治：persistVerthys 已在上方 await 调用（取消防抖，立即落盘）

    showToast(`已删除 ${ids.length} 张照片`);
    selectedPhotoIds.value = new Set();
    selectMode.value = false;
  };

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
    toggleSelectAll,
    cancelSelectMode,
    onDelete,
    onDeleteBtn,
    onPhotoClick,
  };
}
