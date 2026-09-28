/**
 * photo-album/usePhotoDelete.ts — 拾光模块删除层 composable
 *
 * 职责：管理单张删除、批量删除、选择模式。
 * 从原 PhotoAlbum.vue 提取，保持 100% 功能不变。
 *
 * 设计要点：
 * - 接收 usePhotoData 返回值中的 photos/isTauri + 全局 Toast 中心的 showError/showToast（依赖注入）
 * - onView 由外部传入（来自 usePhotoViewer），选择模式下拦截点击改为切换选中
 * - showToast 由外部传入，用于删除成功提示
 * - onDelete 基于 metaId 判断（非 meta），重启后占位项也能正确删除 verthys 记录
 * - onDeleteBtn（右上角按钮）仅切换选择模式，不承担删除动作；
 *   真实删除由选择栏 onDeleteSelected 拉起二次确认，confirmDelete → executeBatchDelete 执行
 * - onDeleteBtn 批量删除合并为单次 flush（deleteAndPersistBatch + persistVerthys）
 * - shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
 */
import { ref, computed, type ShallowRef } from "vue";
import { verthysDeleteRecord, verthysForgetHashes, verthysGcOrphanChunks } from "../../lib/verthys";
import {
  persistVerthysDetailed, deleteAndPersistBatch, setModuleCache,
  invalidateSummaryRecord, invalidateFullRecord, invalidateScannedRecord,
} from "../../lib/keyManager";
import { removeShallowItems } from "../../utils/shallow-array";
import type { PhotoEntry } from "./types";
import type { PhotoMeta } from "../../lib/crypto";
import { isSlimLayout } from "../../constants/crypto_const";
import { revokeThumbUrl } from "./utils";

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
  /**
   * 按 metaId 强制解密元数据（来自 usePhotoData::decryptPhotoMeta）。
   *
   * 占位项（重启后 meta 未解密）删除时需要 chunkIds 级联与 fileHash
   * 去重锁释放，此回调在 ph.meta 缺失时兜底补齐；未注入时退化为
   * 「仅删 meta 记录」的旧行为（chunk 残留由孤儿 GC 台账兜底）。
   */
  resolveMeta?: (metaId: number) => Promise<PhotoMeta | null>;
  /**
   * 按 metaId 解析逐块记录 ID（来自 chunk-refs 的块集分流）。
   *
   * 瘦身布局的逐块 ID 在块集记录内，级联删除需先解析；未注入时退化为
   * 「使用索引内联引用」的旧行为（块集残留由孤儿台账 GC 兜底）。
   */
  resolveChunkIds?: (metaId: number, meta: PhotoMeta) => Promise<number[]>;
}

export function usePhotoDelete(params: UsePhotoDeleteParams) {
  const { photos, isTauri, onView, showError, showToast, resolveMeta, resolveChunkIds } = params;

  /* ===== 删除 ===== */
  const onDelete = async (id: number) => {
    const ph = photos.value.find(p => p.id === id);
    // 修复：删除判断基于 metaId（始终存在）而非 meta（可能未解密）
    //    旧实现 if (ph?.meta && isTauri) 在重启后 meta 未解密时跳过整个 verthys 删除，
    //    导致：UI 移除了照片，但 verthys 记录仍在磁盘 → 重启后"删除的照片复活"。
    if (isTauri && ph?.metaId) {
      // 占位项兜底：meta 未解密时强制解密一次，补齐 chunk 级联与去重锁释放所需字段
      const meta: PhotoMeta | null = ph.meta ?? (await (resolveMeta?.(ph.metaId) ?? null));
      // 逐块引用解析：瘦身布局的逐块 ID 在块集记录内（解析失败退化为内联引用）
      let chunkIds = meta?.chunkIds ?? [];
      if (meta && isSlimLayout(meta) && meta.chunkSetId && resolveChunkIds) {
        try {
          chunkIds = await resolveChunkIds(ph.metaId, meta);
        } catch (e) {
          console.warn(`[onDelete] 块集解析失败，级联改用内联引用: ${ph.metaId}`, e);
        }
      }
      // 删除 meta 记录（新格式的 chunk 数据已内联时删 meta 即彻底清除）
      try { await verthysDeleteRecord(ph.metaId); } catch { /* 删除失败静默 */ }
      // 同时失效两层缓存（摘要 + 全量），杜绝删除复活
      invalidateSummaryRecord(ph.metaId);
      invalidateFullRecord(ph.metaId);
      invalidateScannedRecord(ph.metaId);
      // 外置 chunk 级联删除（新外置格式与旧格式共用 chunkIds 字段）
      if (chunkIds.length > 0) {
        for (const cid of chunkIds) {
          try { await verthysDeleteRecord(cid); } catch { /* 删除失败静默 */ }
          // chunk 记录同样失效两层缓存
          invalidateSummaryRecord(cid);
          invalidateFullRecord(cid);
          invalidateScannedRecord(cid);
        }
      }
      // 索引瘦身布局：缩略图独立记录级联删除（与 chunk 同级处理）
      const thumbId = meta?.thumbId;
      if (typeof thumbId === "number" && thumbId > 0) {
        try { await verthysDeleteRecord(thumbId); } catch { /* 删除失败静默 */ }
        invalidateSummaryRecord(thumbId);
        invalidateFullRecord(thumbId);
        invalidateScannedRecord(thumbId);
      }
      // 释放去重锁（best-effort：失败仅影响「再导入去重」，不影响删除结果）
      if (typeof meta?.fileHash === "string" && meta.fileHash.length > 0) {
        try { await verthysForgetHashes([meta.fileHash]); } catch (e) {
          console.warn("[onDelete] 去重锁释放失败（不影响删除结果）", e);
        }
      }
    }
    // 浏览器模式：释放 Blob URL；缩略图 Blob URL 同时释放（条目即将从列表移除）
    if (ph?.blobUrl) URL.revokeObjectURL(ph.blobUrl);
    if (ph?.thumb) revokeThumbUrl(ph.thumb);
    // 项2：shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
    removeShallowItems(photos, p => p.id === id);
    // 更新缓存
    setModuleCache("photos", photos.value);
    // 修复：持久化删除操作到磁盘 + 三态判定
    //    旧实现仅 try/catch 吞掉异常，忽略 persistVerthys 返回的 false（flush 失败），
    //    导致删除操作未落盘 → 重启后"删除的照片复活"。
    //    判别式：not_persisted（flush 失败）才提示可能恢复；partial_persisted
    //    表示数据已 fsync 落盘（仅结构自查告警），以低噪 warning 提示。
    if (isTauri) {
      let outcome: Awaited<ReturnType<typeof persistVerthysDetailed>> = { kind: "ok" };
      try {
        outcome = await persistVerthysDetailed();
      } catch (e) {
        console.error("[onDelete] persistVerthysDetailed 异常", e);
        outcome = { kind: "not_persisted", reason: String(e) };
      }
      if (outcome.kind === "not_persisted") {
        showError("删除操作持久化失败，重启后照片可能恢复。请重试或重新删除。");
      } else if (outcome.kind === "partial_persisted") {
        showToast(`删除操作已落盘（校验警告）：${outcome.reason}`);
      }
    }
  };

  /* ===== 选择删除模式 ===== */
  const selectMode = ref(false);
  const selectedPhotoIds = ref(new Set<number>());

  /* ===== 删除二次确认（复用 ConfirmDelete 弹窗） ===== */
  const showDeleteConfirm = ref(false);
  /** 待确认删除的照片数量（确认窗口文案数据源，仅在确认弹窗打开期间有意义） */
  const deleteConfirmCount = ref(0);

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
    // 空选时按钮处于禁用态，此处为事件兜底
    if (selectedPhotoIds.value.size === 0) return;
    deleteConfirmCount.value = selectedPhotoIds.value.size;
    showDeleteConfirm.value = true;
  };

  /** 取消删除确认：仅关闭确认窗口，保持选择模式与已选状态不变 */
  const cancelDeleteConfirm = () => {
    showDeleteConfirm.value = false;
  };

  /** 确认删除：关闭确认窗口后执行批量删除 */
  const confirmDelete = async () => {
    showDeleteConfirm.value = false;
    await executeBatchDelete();
  };

  /**
   * 执行批量删除（不含确认交互，由 confirmDelete 调用）
   *
   * 批量删除必须合并为单次 flush：
   *   旧实现循环逐张 onDelete(id) → 每张 verthysDeleteRecord + persistVerthys = 2N 次 IPC + N 次事务提交（IO 风暴）
   *   新实现收集全部 metaId + chunkIds 一次性 deleteAndPersistBatch → 1 次 IPC + 1 次事务提交（恒定 IO）
   *   无论删除多少张照片，磁盘写入量恒定，仅与索引区大小相关。
   */
  const executeBatchDelete = async () => {
    // 批量删除：收集全部待删除照片 + 对应记录 ID（metaId + 外置 chunkIds）
    const ids = Array.from(selectedPhotoIds.value);
    const photosToRemove = photos.value.filter(p => ids.includes(p.id));

    // 占位项兜底：对 meta 未解密的照片强制解密（并发上限 4，避免 IPC 风暴），
    // 补齐 chunk 级联 ID 与去重锁哈希；解密失败不阻断删除（残留交孤儿 GC 台账兜底）
    const resolvedMetaMap = new Map<number, PhotoMeta>();
    const pendingResolve = photosToRemove.filter(p => !p.meta && p.metaId);
    if (resolveMeta && pendingResolve.length > 0) {
      const CONCURRENCY = 4;
      let cursor = 0;
      const runNext = async (): Promise<void> => {
        while (cursor < pendingResolve.length) {
          const ph = pendingResolve[cursor++];
          try {
            const meta = await resolveMeta(ph.metaId!);
            if (meta) resolvedMetaMap.set(ph.metaId!, meta);
          } catch { /* 解密失败不阻断删除；残留块记录交孤儿 GC 兜底 */ }
        }
      };
      await Promise.all(
        Array.from({ length: Math.min(CONCURRENCY, pendingResolve.length) }, runNext),
      );
    }

    // 块引用解析：瘦身布局的逐块 ID 在块集记录内，既有布局在索引内联
    const refs = new Map<number, { chunkIds: number[]; thumbId: number }>();
    const resolveIds = async (metaId: number, meta: PhotoMeta | undefined | null) => {
      if (!meta) {
        refs.set(metaId, { chunkIds: [], thumbId: 0 });
        return;
      }
      let chunkIds = meta.chunkIds ?? [];
      const thumbId = meta.thumbId ?? 0;
      if (isSlimLayout(meta) && meta.chunkSetId && resolveChunkIds) {
        try {
          chunkIds = await resolveChunkIds(metaId, meta);
        } catch (e) {
          // 块集不可读：级联改用索引内联引用（若有），残留交孤儿台账 GC 兜底
          console.warn(`[executeBatchDelete] 块集解析失败，级联改用内联引用: ${metaId}`, e);
        }
      }
      refs.set(metaId, { chunkIds, thumbId });
    };
    for (const ph of photosToRemove) {
      if (!ph.metaId) continue;
      await resolveIds(ph.metaId, ph.meta ?? resolvedMetaMap.get(ph.metaId) ?? null);
    }

    const allRecordIds: number[] = [];
    for (const ph of photosToRemove) {
      if (ph.metaId) allRecordIds.push(ph.metaId);
      const r = ph.metaId ? refs.get(ph.metaId) : undefined;
      if (r) {
        for (const cid of r.chunkIds) allRecordIds.push(cid);
        // 索引瘦身布局：缩略图独立记录随索引一并删除（否则成为持久化孤儿）
        if (r.thumbId > 0) allRecordIds.push(r.thumbId);
      }
    }

    if (isTauri && allRecordIds.length > 0) {
      // 单次 IPC + 单次事务提交（批量删除合并单次 flush）
      //    deleteAndPersistBatch 内部：全部 ID 加入 pendingDeletionIds →
      //    verthysDeleteRecords(ids) 一次 IPC → worker 单次 vtxn_commit →
      //    防抖调度单次 flush（300ms 窗口）
      try {
        await deleteAndPersistBatch(allRecordIds);
        // 修复：await persistVerthysDetailed 强制立即落盘（根治删除后复活）+ 三态判定
        //
        // 原缺陷：deleteAndPersistBatch 仅防抖调度 flush（300ms），不等待落盘
        //   即返回。应用退出 → 防抖 flush 未执行 → 磁盘仍含已删照片 → "删除后复活"。
        //
        // 修复：await persistVerthysDetailed 取消防抖定时器，立即 flush 落盘。
        //   判别式：not_persisted（flush 失败）才提示可能恢复；
        //   partial_persisted 表示数据已 fsync（仅结构自查告警），低噪 warning。
        let outcome: Awaited<ReturnType<typeof persistVerthysDetailed>> = { kind: "ok" };
        try {
          outcome = await persistVerthysDetailed();
        } catch (e) {
          console.error("[executeBatchDelete] persistVerthysDetailed 异常", e);
          outcome = { kind: "not_persisted", reason: String(e) };
        }
        if (outcome.kind === "not_persisted") {
          showError("删除操作持久化失败，重启后照片可能恢复。请重试或重新删除。");
        } else if (outcome.kind === "partial_persisted") {
          showToast(`删除操作已落盘（校验警告）：${outcome.reason}`);
        }

        // 删除成功后释放去重锁（WAL 删除墓碑）：被删照片可重新导入。
        // 覆盖已加载 meta 与本次强制解密的 meta；best-effort——失败仅
        // 影响「再导入去重」（会被视为已导入而跳过），不影响删除结果本身
        const forgetHashes: string[] = [];
        for (const ph of photosToRemove) {
          const fh = ph.meta?.fileHash ?? resolvedMetaMap.get(ph.metaId!)?.fileHash;
          if (typeof fh === "string" && fh.length > 0) forgetHashes.push(fh);
        }
        if (forgetHashes.length > 0) {
          try {
            await verthysForgetHashes(forgetHashes);
          } catch (e) {
            console.warn("[executeBatchDelete] 去重锁释放失败（不影响删除结果）", e);
          }
        }

        // 归属残留兜底：删除路径未覆盖的孤儿块记录由后端台账 GC 清理
        // （如「块已落库但 meta 从未提交」的崩溃残留）。无活跃导入会话，
        // best-effort——失败仅推迟到下次触发时机，不影响删除结果。
        try {
          const collected = await verthysGcOrphanChunks();
          if (collected > 0) {
            console.info(`[executeBatchDelete] 孤儿块 GC 清理 ${collected} 条残留块记录`);
          }
        } catch (e) {
          console.warn("[executeBatchDelete] 孤儿块 GC 失败（可下次再触发）", e);
        }
      } catch (e) {
        console.warn("[executeBatchDelete] deleteAndPersistBatch 失败", e);
        showError("删除失败，请重试");
      }
      // 失效两层缓存（摘要 + 全量 + 扫描回退），杜绝删除复活
      for (const rid of allRecordIds) {
        invalidateSummaryRecord(rid);
        invalidateFullRecord(rid);
        invalidateScannedRecord(rid);
      }
    }

    // 浏览器模式：释放 Blob URL；缩略图 Blob URL 统一回收（含 Tauri 模式）
    for (const ph of photosToRemove) {
      if (ph.blobUrl) URL.revokeObjectURL(ph.blobUrl);
      if (ph.thumb) revokeThumbUrl(ph.thumb);
    }
    // 删除按钮完毕的瞬间移除对应内容，消除内容实际删除之间的空白间隔，做到无缝衔接
    const removedIdSet = new Set(ids);
    // 项2：shallowRef 下 filter 需用 removeShallowItems 触发 triggerRef
    removeShallowItems(photos, p => removedIdSet.has(p.id));
    // 更新缓存
    setModuleCache("photos", photos.value);
    // 修复：persistVerthys 已在上方 await 调用（取消防抖，立即落盘）

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
    onDeleteSelected,
    showDeleteConfirm,
    deleteConfirmCount,
    confirmDelete,
    cancelDeleteConfirm,
    onPhotoClick,
  };
}
