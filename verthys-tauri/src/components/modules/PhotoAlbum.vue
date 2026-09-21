<!--
  PhotoAlbum.vue — 拾光模块入口文件

  ★ 入口文件单一职责（不可突破红线）：
    1. 身份定性：仅作为应用容器装配器、依赖加载调度器、生命周期总管家、安全前置校验闸门。
    2. 不可突破红线：所有业务逻辑、数据处理、接口实现、页面交互必须全部下沉至
       composables/photo-album/ 分层目录，入口零业务侵入。

  职责边界：
    - 装配各 composable 并完成依赖注入（applyDependencies）
    - 调度 onMounted/onUnmounted 生命周期（initLifecycle / cleanupLifecycle）
    - 安全前置校验：isModuleReady + ensurePhotoKey 闸门
    - 渲染模板（视图层声明，不含业务逻辑）

  分层目录（composables/photo-album/）：
    - usePhotoToast        Toast 反馈中心（统一提示）
    - usePhotoData         核心数据层（列表/虚拟滚动/按需解密/加载）
    - usePhotoImport       导入层（文件选择/加密入库）
    - usePhotoExport       导出层（对话框/三种格式导出）
    - usePhotoViewer       查看器层（内存预览/缩放）
    - usePhotoParse        解析层（.venc 解密/导入）
    - usePhotoDelete       删除层（单删/批删/选择模式）
    - usePhotoPrivacy      隐私模式层（防截屏）
    - usePhotoInteraction  交互层（卡片视差效果）
    - useModuleDialogGuard 弹窗清理守卫（页面覆盖根治）
-->
<template>
  <div class="photo-album">
    <!-- 顶部错误提示弹窗 -->
    <Teleport to="body">
      <transition name="err-toast">
        <div v-if="errorMsg" class="error-toast glass"><span class="toast-dot"></span>{{ errorMsg }}</div>
      </transition>
    </Teleport>

    <!-- 顶部栏 -->
    <div class="album-top glass">
      <div class="top-left">
        <span class="album-title">拾光</span>
        <span class="album-count">{{ photos.length }} 张</span>
        <span class="enc-badge" v-tip="'主密钥已就绪'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          加密
        </span>
      </div>
      <div class="top-right">
        <button class="btn btn-sm privacy-btn" :class="{ on: privacyMode }" @click="togglePrivacy" v-tip="privacyMode ? '关闭隐私模式' : '开启隐私模式（防截屏）'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          <span v-if="privacyMode" class="privacy-dot"></span>
        </button>
        <button class="btn btn-sm export-top-btn" @click="openExportDialog" :disabled="photos.length === 0" v-tip="'导出加密格式'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
          导出
        </button>
        <button class="btn btn-sm export-top-btn" @click="openParseDialog" v-tip="'解析加密文件'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
          解析
        </button>
        <ActionButton
          :label="importing ? `加密中…${importProgress}%` : '导入照片'"
          :loading="importing"
          @click="onImport"
        />
        <button class="btn btn-sm del-top-btn" :class="{ active: selectMode }" @click="onDeleteBtn" v-tip="selectMode ? (selectedPhotoIds.size > 0 ? `删除选中 (${selectedPhotoIds.size})` : '取消选择') : '选择删除'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
        </button>
      </div>
    </div>

    <!-- ★ 顶部导入进度条复用 QuantumProgressFlow（量子能量导流通道，全局统一进度条组件）
         EWMA 滑动窗口加权 ETA + requestAnimationFrame 帧对齐 + 速率骤降检测 -->
    <QuantumProgressFlow
      :loading="importing"
      :percent="importProgress"
      :message="importStatus"
      :elapsed="importElapsed"
      :show-meta="true"
      :show-loader="false"
    />

    <!-- 选择模式操作栏 -->
    <div v-if="selectMode" class="select-bar glass">
      <div class="select-bar-left">
        <button class="btn btn-sm select-all-btn" @click="toggleSelectAll">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <rect x="3" y="3" width="18" height="18" rx="2"/>
            <polyline v-if="allSelected" points="20 6 9 17 4 12"/>
          </svg>
          {{ allSelected ? '取消全选' : '全选' }}
        </button>
        <span class="select-count">
          已选 <strong>{{ selectedPhotoIds.size }}</strong> / {{ photos.length }} 张
        </span>
      </div>
      <div class="select-bar-right">
        <button class="btn btn-sm select-cancel-btn" @click="cancelSelectMode">取消</button>
        <button
          class="btn btn-sm select-delete-btn"
          :disabled="selectedPhotoIds.size === 0"
          @click="onDeleteBtn"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          删除选中{{ selectedPhotoIds.size > 0 ? ` (${selectedPhotoIds.size})` : '' }}
        </button>
      </div>
    </div>

    <!-- Masonry 瀑布流（滚动容器与列布局分离，确保滚轮垂直滚动正常） -->
    <div class="masonry-scroll" ref="scrollRef" @scroll="onScroll">
      <!-- 非阻塞加载：无底板居中展示，加载完成自动消失 -->
      <CosmicLoading :show="photosLoading && photos.length === 0" text="正在解密加载照片…" />

      <!-- ★ 虚拟滚动容器（相册列表强制采用虚拟滚动）：
           绝对定位网格，仅渲染可视区域 + buffer 行对应的项目。
           上万照片也只渲染数十 DOM 节点，消除 Vue 响应式 diff 与全量布局开销。
           容器高度 = 总行数 × 行高，撑开滚动条；每个 masonry-item 用 translate3d 精确定位。 -->
      <div v-if="photos.length > 0" class="masonry-cols" :style="{ height: totalHeight + 'px' }">
        <div
          v-for="ph in visiblePhotos"
          :key="ph.id"
          class="masonry-item"
          :class="{ selected: selectMode && selectedPhotoIds.has(ph.id), 'no-anim': animationDone }"
          :style="{ transform: `translate3d(${ph._left}px, ${ph._top}px, 0)`, width: itemWidth + 'px', height: itemWidth + 'px' }"
          @mousemove="onPhotoMove($event)"
          @mouseleave="onPhotoLeave($event)"
          @click="onPhotoClick(ph)"
        >
          <div class="photo-card glass">
            <div class="photo-thumb" :style="{ backgroundImage: ph.thumb }">
              <div class="photo-overlay">
                <span class="photo-name">{{ ph.name }}</span>
                <span class="photo-size">{{ ph.size }}</span>
              </div>
              <div class="enc-mark" v-tip="'XChaCha20-Poly1305 加密'">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
              </div>
              <div v-if="selectMode" class="photo-select-mark" :class="{ checked: selectedPhotoIds.has(ph.id) }">
                <svg v-if="selectedPhotoIds.has(ph.id)" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
              </div>
            </div>
            <div class="photo-shine"></div>
          </div>
        </div>
      </div>

      <CosmicEmpty v-if="!photosLoading && photos.length === 0" text="暂无照片" hint="点击「导入照片」添加 · 自动 XChaCha20 加密" />
    </div>

    <!-- 沉浸式查看器（内存预览，不落地，滚轮缩放 + 拖拽平移 + 双击复位） -->
    <div v-if="viewer" class="viewer" :class="{ blurred: viewerBlurred }" @click="closeViewer">
      <div class="viewer-content" :style="{ '--viewer-scale': viewerScale }" @click.stop @wheel.prevent="onViewerWheel">
        <img
          v-if="viewerSrc"
          class="viewer-image"
          :class="{ dragging: viewerDragging }"
          :src="viewerSrc"
          alt=""
          draggable="false"
          :style="{ transform: `translate(${viewerOffsetX}px, ${viewerOffsetY}px) scale(${viewerScale})`, cursor: viewerDragging ? 'grabbing' : viewerScale > 1 ? 'grab' : 'default' }"
          @mousedown="onViewerMouseDown"
          @dblclick.prevent="onViewerDoubleClick"
        />
        <div class="viewer-info">
          <span class="viewer-name">{{ viewerName }}</span>
        </div>
      </div>
    </div>

    <!-- 导出对话框 -->
    <div v-if="showExportDialog" class="export-dialog-overlay" @click.self="closeExportDialog">
      <div class="export-dialog glass">
        <div class="ed-header">
          <div class="ed-title-row">
            <svg class="ed-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            <span class="ed-title">导出加密照片</span>
          </div>
          <button class="ed-close" @click="closeExportDialog" :disabled="exporting">×</button>
        </div>

        <div class="ed-body">
          <!-- 照片选择区 -->
          <div class="ed-section">
            <div class="ed-section-header">
              <span class="ed-section-title">选择照片</span>
              <div class="ed-section-actions">
                <button class="ed-mini-btn" @click="selectAllPhotos" :disabled="exporting">全选</button>
                <button class="ed-mini-btn" @click="deselectAllPhotos" :disabled="exporting">取消</button>
                <span class="ed-selected-count">已选 {{ exportSelectedIds.size }} / {{ photos.length }} 张</span>
              </div>
            </div>
            <div class="ed-photo-grid">
              <div
                v-for="ph in photos"
                :key="ph.id"
                class="ed-photo-item"
                :class="{ selected: exportSelectedIds.has(ph.id) }"
                @click="togglePhotoSelect(ph.id)"
              >
                <div class="ed-photo-thumb" :style="{ backgroundImage: ph.thumb }"></div>
                <span class="ed-photo-name">{{ ph.name }}</span>
                <span class="ed-photo-size">{{ ph.size }}</span>
              </div>
            </div>
          </div>

          <!-- 加密密钥区（PNG 明文导出模式不需要） -->
          <div v-if="exportFormat !== 'png'" class="ed-section">
            <div class="ed-section-header">
              <span class="ed-section-title">加密密钥（自动生成随机令牌）</span>
            </div>
            <div class="ed-token-display">
              <code class="ed-token-code" @click="copyExportToken" v-tip="'点击复制密钥'">{{ exportToken }}</code>
              <div class="ed-token-actions">
                <button class="ed-token-btn ed-token-btn--spin" @click="regenerateExportToken" :disabled="exporting" v-tip="'重新生成随机令牌'">
                  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
                </button>
                <button class="ed-token-btn" :class="{ 'is-copied': tokenCopied }" @click="copyExportToken" v-tip="'复制密钥'">
                  <svg v-if="tokenCopied" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                  <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                </button>
              </div>
            </div>
            <div class="ed-token-info">
              <div class="ed-token-strength">
                <span>强度:</span>
                <div class="ed-strength-bar"><div class="ed-strength-fill" :style="{ width: '100%' }"></div></div>
                <span class="ed-strength-label">256-bit</span>
              </div>
              <div class="ed-token-hint">此密钥用于加密导出文件，请妥善保管。没有此密钥无法解密。</div>
            </div>
          </div>

          <!-- 导出选项区 -->
          <div class="ed-section">
            <div class="ed-section-header">
              <span class="ed-section-title">导出选项</span>
            </div>
            <div class="ed-format-opts">
              <label class="ed-radio" :class="{ active: exportFormat === 'single' }">
                <input type="radio" v-model="exportFormat" value="single" :disabled="exporting" />
                <div class="ed-radio-content">
                  <span class="ed-radio-title">单个打包文件</span>
                  <span class="ed-radio-desc">所有照片打包为一个 .venc 文件</span>
                </div>
              </label>
              <label class="ed-radio" :class="{ active: exportFormat === 'multiple' }">
                <input type="radio" v-model="exportFormat" value="multiple" :disabled="exporting" />
                <div class="ed-radio-content">
                  <span class="ed-radio-title">多个独立文件</span>
                  <span class="ed-radio-desc">每张照片导出为独立 .venc 文件</span>
                </div>
              </label>
              <label class="ed-radio" :class="{ active: exportFormat === 'png' }">
                <input type="radio" v-model="exportFormat" value="png" :disabled="exporting" />
                <div class="ed-radio-content">
                  <span class="ed-radio-title">PNG 图片</span>
                  <span class="ed-radio-desc">导出为 .png，非 PNG 自动转换</span>
                </div>
              </label>
            </div>
            <div class="ed-path-row">
              <span class="ed-path-label">保存位置</span>
              <input class="ed-path-input" :value="exportPath || '点击右侧按钮选择…'" readonly @click="chooseExportPath" />
              <button class="ed-mini-btn ed-browse-btn" @click="chooseExportPath" :disabled="exporting">浏览</button>
            </div>
            <div class="ed-summary">
              <div class="ed-summary-item">
                <span class="ed-summary-label">照片数</span>
                <span class="ed-summary-value">{{ exportSelectedIds.size }} 张</span>
              </div>
              <div class="ed-summary-item">
                <span class="ed-summary-label">格式</span>
                <span class="ed-summary-value">{{ exportFormat === 'single' ? '单文件' : exportFormat === 'multiple' ? '多文件' : 'PNG 图片' }}</span>
              </div>
              <div class="ed-summary-item">
                <span class="ed-summary-label">加密</span>
                <span class="ed-summary-value">{{ exportFormat === 'png' ? '无（明文）' : 'AES-256-GCM' }}</span>
              </div>
            </div>
          </div>

          <!-- 导出进度 -->
          <div v-if="exporting" class="ed-progress">
            <div class="progress-bar"><div class="progress-fill" :style="{ width: exportProgress + '%' }"></div></div>
            <span class="progress-text">{{ exportStatus }}</span>
          </div>
        </div>

        <!-- 操作按钮 -->
        <div class="ed-footer">
          <button class="btn btn-sm" @click="closeExportDialog" :disabled="exporting">取消</button>
          <button
            class="btn btn-sm ed-confirm"
            @click="doExport"
            :disabled="exporting || exportSelectedIds.size === 0 || !exportPath"
          >
            {{ exporting ? '导出中…' : `开始导出 (${exportSelectedIds.size} 张)` }}
          </button>
        </div>
      </div>
    </div>

    <!-- 解析对话框（复用子密钥验证窗口 CosmicOverlay + kv-* 样式） -->
    <!-- ★ 单一 v-if/v-else-if 链：互斥状态机，避免多链导致元素同时显示
         状态：fileLoading → parsing → importingParsed → parsedResults → 初始态 -->
    <CosmicOverlay :show="showParseDialog" width="420px" @close="closeParseDialog">
      <div class="kv-title">解析加密文件</div>
      <div class="kv-desc">选择 .venc 文件并输入加密令牌以还原照片</div>
      <!-- 1. 文件读取中 → 进度条（不显示文件选择行/密钥输入框） -->
      <QuantumProgressFlow
        v-if="fileLoading"
        :loading="fileLoading"
        :percent="fileLoadingPercent"
        :message="fileLoadingMsg"
        :show-loader="false"
      />
      <!-- 2. 解析中 → 进度条（不显示文件选择行/密钥输入框） -->
      <QuantumProgressFlow
        v-else-if="parsing"
        :loading="parsing"
        :percent="parsingPercent"
        :message="parsingMsg"
        :show-loader="false"
      />
      <!-- 3. 导入到拾光中 → 进度条（不显示文件选择行/密钥输入框） -->
      <QuantumProgressFlow
        v-else-if="importingParsed"
        :loading="importingParsed"
        :percent="importProgress"
        :message="importStatus"
        :show-loader="false"
      />
      <!-- 4. 解析结果区（有结果且非导入中）→ 预览 + 导入按钮（不显示文件选择行/密钥输入框） -->
      <div v-else-if="parsedPhotos.length > 0" class="parse-result">
        <div class="parse-result-title">已解析 {{ parsedPhotos.length }} 张照片</div>
        <div class="parse-preview-grid">
          <div v-for="(ph, i) in parsedPhotos" :key="i" class="parse-preview-item">
            <div class="parse-preview-thumb" :style="{ backgroundImage: ph.thumb }"></div>
            <span class="parse-preview-name">{{ ph.name }}</span>
          </div>
        </div>
        <div class="kv-actions">
          <button class="btn btn-primary kv-confirm" @click="importParsedPhotos">导入到拾光</button>
        </div>
      </div>
      <!-- 5. 初始态：文件选择行 + 令牌输入框 + 开始解析按钮 -->
      <template v-else>
        <div class="parse-file-row">
          <input class="kv-input parse-file-input" :value="parseFileName" readonly placeholder="点击选择或拖拽 .venc 文件" />
          <button class="btn btn-sm parse-browse-btn" @click="chooseParseFile">浏览</button>
        </div>
        <div style="height: 12px;"></div>
        <input class="kv-input parse-token-input" v-model="parseToken" placeholder="粘贴导出时的加密密钥" />
        <div class="kv-actions">
          <button class="btn btn-primary kv-confirm" @click="doParse" :disabled="!parseFileData || !parseToken">
            开始解析
          </button>
        </div>
      </template>
    </CosmicOverlay>

    <!-- 导出完成状态感知（顶部，复用 clip-toast 样式） -->
    <transition name="toast">
      <div v-if="exportDoneToast" class="clip-toast glass clip-toast--top clip-toast--over-dialog" :class="exportDoneToast.type === 'error' ? 'clip-toast--error' : 'clip-toast--success'"><span class="toast-dot"></span>{{ exportDoneToast.msg }}</div>
    </transition>
    <!-- 复制提示（复用全局 clip-toast 样式） -->
    <transition name="toast">
      <div v-if="copiedToast" class="clip-toast glass clip-toast--over-dialog"><span class="toast-dot"></span>已复制到剪贴板</div>
    </transition>
    <transition name="toast">
      <div v-if="toastMsg" class="clip-toast glass clip-toast--over-dialog"><span class="toast-dot"></span>{{ toastMsg }}</div>
    </transition>
  </div>
</template>

<script setup lang="ts">
/**
 * ★ 入口文件单一职责实现
 *
 * 仅做四件事：
 *   1. 装配 composable（applyDependencies）
 *   2. 调度生命周期（initLifecycle / cleanupLifecycle）
 *   3. 安全前置校验闸门（isModuleReady + ensurePhotoKey）
 *   4. 渲染模板
 *
 * 业务逻辑零侵入：所有加密/解密、verthys 读写、数据处理、交互逻辑均下沉至
 * composables/photo-album/ 分层目录，入口仅通过依赖注入装配。
 */
import { onMounted, onUnmounted, defineAsyncComponent } from "vue";
import { isModuleReady } from "../../lib/keyManager";
import { tryGc } from "../../utils/gc";
import ActionButton from "../common/verthys-ui/ActionButton.vue";
import CosmicLoading from "../common/cosmic/CosmicLoading.vue";
import CosmicEmpty from "../common/cosmic/CosmicEmpty.vue";
// 大型弹窗组件级懒加载（遵循项目硬约束：大型弹窗使用 defineAsyncComponent）
const CosmicOverlay = defineAsyncComponent(() => import("../common/cosmic/CosmicOverlay.vue"));
// ★ 量子能量导流通道进度条（全局统一进度条组件，替代已删除的 QuantumProgressBar）
const QuantumProgressFlow = defineAsyncComponent(() => import("../common/cosmic/QuantumProgressFlow.vue"));

/* ===== 分层 composable 装配（依赖加载调度器） ===== */
import { usePhotoToast } from "../../composables/photo-album/usePhotoToast";
import { usePhotoData } from "../../composables/photo-album/usePhotoData";
import { usePhotoImport } from "../../composables/photo-album/usePhotoImport";
import { usePhotoExport } from "../../composables/photo-album/usePhotoExport";
import { usePhotoViewer } from "../../composables/photo-album/usePhotoViewer";
import { usePhotoParse } from "../../composables/photo-album/usePhotoParse";
import { usePhotoDelete } from "../../composables/photo-album/usePhotoDelete";
import { usePhotoPrivacy } from "../../composables/photo-album/usePhotoPrivacy";
import { usePhotoInteraction } from "../../composables/photo-album/usePhotoInteraction";
import { useModuleDialogGuard } from "../../composables/useModuleDialogGuard";

/* ---------- 1. Toast 反馈中心（最先装配，后续 composable 依赖其 showError 等） ---------- */
const {
  errorMsg, toastMsg, exportDoneToast, copiedToast,
  showError, showToast, showExportDone, showCopied,
} = usePhotoToast();

/* ---------- 2. 核心数据层（提供 photos / photoKey / isTauri / 虚拟滚动 / 按需解密） ---------- */
const {
  photos, photoKey, isTauri, photosLoading, animationDone,
  scrollRef, scrollTop, viewportHeight, containerWidth, columns,
  itemWidth, rowHeight, totalRows, totalHeight, visiblePhotos,
  onScroll, updateLayout, resizeObserver,
  initVirtualScroll, destroyVirtualScroll,
  decryptPhotoMeta, loadPhotos, ensurePhotoKey,
} = usePhotoData();

/* ---------- 3. 查看器层（依赖 usePhotoData 的 photos/photoKey/decryptPhotoMeta） ---------- */
const {
  viewer, viewerSrc, viewerName, viewerBlurred, viewerScale,
  viewerOffsetX, viewerOffsetY, viewerDragging,
  onView, closeViewer, onViewerWheel, onViewerMouseDown, onViewerDoubleClick,
  onBlur, onFocus,
  cleanup: cleanupViewer,
} = usePhotoViewer({
  photos, photoKey, isTauri, ensurePhotoKey, decryptPhotoMeta, showError,
});

/* ---------- 4. 导入层 ---------- */
const {
  importing, importProgress, importStatus,
  /* ★ Comprehensive_optimization：新增耗时与 ETA（供 QuantumProgressFlow 使用） */
  importElapsed, importEta,
  onImport,
  /* ★ Parsed Import：导出 getPipeline 供 usePhotoParse 复用同一流水线实例 */
  getPipeline,
} = usePhotoImport({
  photos, photoKey, isTauri, ensurePhotoKey, showError,
});

/* ---------- 5. 导出层 ---------- */
const {
  showExportDialog, exportSelectedIds, exportToken, exportFormat, exportPath,
  exporting, exportProgress, exportStatus, tokenCopied,
  openExportDialog, closeExportDialog, togglePhotoSelect, selectAllPhotos,
  deselectAllPhotos, regenerateExportToken, copyExportToken, chooseExportPath,
  doExport,
} = usePhotoExport({
  photos, photoKey, isTauri, ensurePhotoKey,
  showError, showExportDone, showCopied,
});

/* ---------- 6. 解析层 ---------- */
const {
  showParseDialog, parseFileName, parseFileData, parseToken, parsing, parsedPhotos,
  // ★ 企业级感知：进度条状态（复用中枢初始化窗口进度条样式，非量子动画）
  fileLoading, fileLoadingPercent, fileLoadingMsg,
  parsingPercent, parsingMsg,
  /* ★ Parsed Import：对话框内导入进度条状态（复用 QuantumProgressFlow 组件） */
  importingParsed,
  openParseDialog, closeParseDialog, chooseParseFile, doParse, importParsedPhotos,
} = usePhotoParse({
  photos, photoKey, isTauri, ensurePhotoKey, showError, showToast,
  /* ★ Parsed Import：复用 usePhotoImport 的流水线实例 + 导入状态 refs
     （对话框内复用 QuantumProgressFlow，导入进度实时反馈，UI 不卡死） */
  getPipeline, importing, importProgress, importStatus, importElapsed, importEta,
});

/* ---------- 7. 删除层（依赖 usePhotoViewer 的 onView 用于非选择模式下的照片点击） ---------- */
const {
  selectMode, selectedPhotoIds, allSelected,
  toggleSelectAll, cancelSelectMode, onDelete, onDeleteBtn, onPhotoClick,
} = usePhotoDelete({
  photos, isTauri, onView, showError, showToast,
});

/* ---------- 8. 隐私模式层 ---------- */
const { privacyMode, togglePrivacy, cleanup: cleanupPrivacy } = usePhotoPrivacy(isTauri);

/* ---------- 9. 交互层（卡片视差效果） ---------- */
const { onPhotoMove, onPhotoLeave, cancel: cancelInteraction } = usePhotoInteraction();

/* ===== 生命周期总管家（onMounted / onUnmounted） ===== */

/**
 * 初始化生命周期：
 *   - 注册窗口失焦/聚焦事件（查看器模糊控制）
 *   - 启动虚拟滚动布局测量 + ResizeObserver（由 usePhotoData.initVirtualScroll 封装）
 *   - 首批照片入场动画 1.5s 后禁用（避免虚拟滚动新进入项重播闪烁）
 *   - 安全前置校验闸门：isModuleReady + ensurePhotoKey 通过后才加载数据
 *   - 浏览器模式降级：使用占位密钥（仅本地演示）
 */
const initLifecycle = () => {
  window.addEventListener("blur", onBlur);
  window.addEventListener("focus", onFocus);

  // ★ 虚拟滚动布局初始化收敛至数据层（initVirtualScroll 内部完成 updateLayout + ResizeObserver 注册）
  initVirtualScroll();

  // 首批照片入场动画播完后禁用，避免虚拟滚动时新进入可视区项重播动画导致闪烁
  setTimeout(() => { animationDone.value = true; }, 1500);

  // ★ 安全前置校验闸门：模块密钥已由 MainView 登录时缓存到 keyManager 会话，直接读取
  if (isTauri) {
    if (isModuleReady("photo") && ensurePhotoKey()) {
      loadPhotos();
    }
  } else {
    // 浏览器模式：使用占位密钥（仅用于本地演示，不涉及真实加密）
    photoKey.value = "browser_demo_key";
  }
};

/**
 * 清理生命周期：
 *   - 移除窗口事件监听
 *   - 取消 rafThrottle 未触发的回调（防止卸载后状态写入空组件）
 *   - 销毁虚拟滚动 ResizeObserver（由 usePhotoData.destroyVirtualScroll 封装）
 *   - 释放查看器 Blob URL（由 usePhotoViewer.cleanup 封装）
 *   - 关闭隐私模式（需会话令牌验证）
 *   - 释放浏览器模式照片 Blob URL
 *   - 清空照片数组释放引用 + 主动触发 V8 Major GC
 *   - 清零模块子密钥（全局密钥由 keyManager 统一管理）
 */
const cleanupLifecycle = () => {
  window.removeEventListener("blur", onBlur);
  window.removeEventListener("focus", onFocus);

  // 取消 rafThrottle 未触发的回调
  onScroll.cancel();
  cancelInteraction();

  // ★ 销毁虚拟滚动（释放 ResizeObserver）
  destroyVirtualScroll();

  // ★ 释放查看器 Blob URL
  cleanupViewer();

  // 关闭隐私模式（fire-and-forget，不阻塞卸载）
  cleanupPrivacy();

  // 释放浏览器模式的 Blob URL
  for (const ph of photos.value) {
    if (ph.blobUrl) URL.revokeObjectURL(ph.blobUrl);
  }

  // ★ 项12：清空照片数组释放引用 + 主动触发 V8 Major GC
  // 数万照片记录在 Vue 响应式系统中持有大量依赖关系，仅清空数组才能让
  // GC 回收整条记录对象图（PhotoEntry + meta + rawBytes + thumb）。
  photos.value = [];

  // 清零模块子密钥（全局密钥由 keyManager 统一管理）
  photoKey.value = "";

  // 主动触发 GC（dev 环境跳过，仅 release 模式生效）
  tryGc();
};

onMounted(initLifecycle);
onUnmounted(cleanupLifecycle);

/* ===== 弹窗清理守卫（页面覆盖根治） =====
 * 切换模块时同步关闭所有 Teleport 弹窗，杜绝残留覆盖。
 * 各弹窗状态由对应 composable 管理，此处仅调用清理函数。 */
useModuleDialogGuard("photos", () => {
  viewer.value = false;
  showExportDialog.value = false;
  showParseDialog.value = false;
});
</script>

<style scoped>
.photo-album { width: 100%; height: 100%; display: flex; flex-direction: column; gap: 14px; overflow: hidden; }

/* 顶部栏 */
.album-top { display: flex; align-items: center; justify-content: space-between; padding: 10px 16px; flex-shrink: 0; animation: slide-down 0.5s var(--ease) both; }
@keyframes slide-down { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
.top-left { display: flex; align-items: center; gap: 8px; }
.album-title { font-size: 13px; color: var(--text-primary); letter-spacing: 1px; }
.album-count { font-size: 10px; color: var(--text-muted); font-family: var(--font); }
.enc-badge { display: flex; align-items: center; gap: 3px; font-size: 9px; color: var(--accent); font-family: var(--font); letter-spacing: 0.5px; padding: 2px 6px; border: 1px solid rgba(0,212,255,0.2); border-radius: 8px; background: rgba(0,212,255,0.05); }
.enc-badge svg { width: 10px; height: 10px; }
.top-right { display: flex; gap: 8px; align-items: center; }
.privacy-btn { position: relative; display: flex; align-items: center; justify-content: center; width: 32px; height: 32px; padding: 0; }
.privacy-btn svg { width: 15px; height: 15px; }
.privacy-btn.on { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.08); }
.privacy-dot { position: absolute; top: 2px; right: 2px; width: 5px; height: 5px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 6px var(--accent); animation: dot-blink 1.5s infinite; }
@keyframes dot-blink { 50% { opacity: 0.3; } }

/* 顶部按钮统一尺寸 */
.export-top-btn, .import-btn { display: flex; align-items: center; gap: 4px; padding: 6px 12px; font-size: 11px; }
.export-top-btn svg, .import-btn svg { width: 13px; height: 13px; }
.del-top-btn { display: flex; align-items: center; justify-content: center; width: 32px; height: 32px; padding: 0; color: var(--text-muted); transition: all 0.2s; }
.del-top-btn svg { width: 14px; height: 14px; }
.del-top-btn:hover { color: var(--danger); border-color: rgba(255,71,87,0.3); background: rgba(255,71,87,0.06); }
.del-top-btn.active { color: var(--danger); border-color: rgba(255,71,87,0.4); background: rgba(255,71,87,0.1); box-shadow: 0 0 8px rgba(255,71,87,0.2); }
.plus { font-weight: 300; }

/* 导入进度 */
.import-progress { display: flex; align-items: center; gap: 12px; padding: 8px 16px; flex-shrink: 0; }
.progress-bar { flex: 1; height: 3px; background: rgba(255,255,255,0.05); border-radius: 2px; overflow: hidden; }
.progress-fill { height: 100%; background: linear-gradient(90deg, var(--accent), #b46cff); transition: width 0.3s var(--ease); border-radius: 2px; }
.progress-text { font-size: 11px; color: var(--text-secondary); font-family: var(--font); white-space: nowrap; }

/* 选择模式操作栏 */
.select-bar { display: flex; align-items: center; justify-content: space-between; padding: 8px 16px; flex-shrink: 0; animation: slide-down 0.3s var(--ease) both; }
.select-bar-left { display: flex; align-items: center; gap: 12px; }
.select-bar-right { display: flex; align-items: center; gap: 8px; }
.select-all-btn { display: flex; align-items: center; gap: 4px; font-size: 11px; }
.select-all-btn svg { width: 13px; height: 13px; }
.select-all-btn:hover { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.06); }
.select-count { font-size: 11px; color: var(--text-secondary); font-family: var(--font); letter-spacing: 0.5px; }
.select-count strong { color: var(--accent); font-weight: 600; }
.select-cancel-btn { font-size: 11px; color: var(--text-muted); }
.select-cancel-btn:hover { color: var(--text-primary); }
.select-delete-btn { display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--danger); border-color: rgba(255,71,87,0.3); background: rgba(255,71,87,0.06); }
.select-delete-btn svg { width: 13px; height: 13px; }
.select-delete-btn:hover:not(:disabled) { background: rgba(255,71,87,0.12); border-color: rgba(255,71,87,0.5); box-shadow: 0 0 8px rgba(255,71,87,0.2); }
.select-delete-btn:disabled { opacity: 0.35; cursor: not-allowed; }

/* Masonry 瀑布流 — 滚动容器与列布局分离 */
.masonry-scroll { flex: 1; overflow-y: auto; overflow-x: hidden; padding-right: 4px; min-height: 0; position: relative; scrollbar-width: thin; scrollbar-color: transparent transparent; }
.masonry-scroll:hover { scrollbar-color: rgba(var(--accent-rgb), 0.25) transparent; }

/* 照片主界面滚动条：默认隐藏，hover 时显示，比全局更宽更明显 */
.masonry-scroll::-webkit-scrollbar { width: 8px; }
.masonry-scroll::-webkit-scrollbar-track { background: transparent; }
.masonry-scroll::-webkit-scrollbar-thumb { background: transparent; border-radius: 4px; }
.masonry-scroll:hover::-webkit-scrollbar-thumb { background: rgba(var(--accent-rgb), 0.25); border-radius: 4px; }
.masonry-scroll:hover::-webkit-scrollbar-thumb:hover { background: rgba(var(--accent-rgb), 0.45); }
/* CSS Grid 行优先布局：照片按行从左至右排列，加载顺序自然正确 */
/* ★ 虚拟滚动：绝对定位网格容器（不再使用 CSS grid，由 JS 精确计算每项 translate3d 定位）
      列数/行高由 JS computeColumns + itemWidth 计算，响应式断点与原媒体查询一致 */
.masonry-cols { position: relative; width: 100%; }
.masonry-item { position: absolute; top: 0; left: 0; cursor: pointer; }

/* 入场动画作用于 .photo-card 子元素，避免与 masonry-item 的 translate3d 定位 transform 冲突
   首批加载播放（animationDone=false）；1.5s 后 no-anim 禁用，防止虚拟滚动新进入项重播闪烁 */
.masonry-item:not(.no-anim) .photo-card { animation: photo-reveal 0.65s cubic-bezier(0.22, 1, 0.36, 1) both; }
.masonry-item.no-anim .photo-card { animation: none; }

/* 高级照片入场动画：从缩放+下移 → 还原，配合逐个动态加载产生行优先瀑布入场效果 */
@keyframes photo-reveal {
  0%   { opacity: 0; transform: scale(0.85) translateY(20px); }
  50%  { opacity: 1; transform: scale(0.97) translateY(4px); }
  100% { opacity: 1; transform: scale(1) translateY(0); }
}

.photo-card { position: relative; overflow: hidden; border-radius: var(--radius); transition: transform 0.3s var(--ease), box-shadow 0.3s var(--ease); will-change: transform; transform-style: preserve-3d; }
.photo-card:hover { box-shadow: 0 16px 40px rgba(0,0,0,0.5), 0 0 20px rgba(0,212,255,0.12); }
.photo-thumb { background-size: cover; background-position: center; position: relative; transition: filter 0.4s var(--ease); filter: saturate(0.85) brightness(0.9); aspect-ratio: 1 / 1; }
.photo-card:hover .photo-thumb { filter: saturate(1.1) brightness(1); }
.photo-overlay { position: absolute; bottom: 0; left: 0; right: 0; padding: 10px 12px; background: linear-gradient(180deg, transparent, rgba(0,0,0,0.85)); opacity: 0; transition: opacity 0.3s; display: flex; justify-content: space-between; align-items: flex-end; }
.photo-card:hover .photo-overlay { opacity: 1; }
.photo-name { font-size: 11px; color: var(--text-primary); font-family: var(--font); }
.photo-size { font-size: 9px; color: var(--accent); font-family: var(--font); letter-spacing: 0.5px; }
.enc-mark { position: absolute; top: 6px; right: 6px; width: 18px; height: 18px; display: flex; align-items: center; justify-content: center; color: var(--accent); opacity: 0.7; }
.enc-mark svg { width: 12px; height: 12px; }

/* 选择删除模式 */
.masonry-item.selected .photo-card { box-shadow: 0 0 0 2px var(--danger), 0 12px 36px rgba(0,0,0,0.5); }
.photo-select-mark { position: absolute; top: 8px; left: 8px; width: 24px; height: 24px; border-radius: 50%; border: 2px solid rgba(255,255,255,0.4); background: rgba(0,0,0,0.68); display: flex; align-items: center; justify-content: center; z-index: 3; transition: background 0.2s, border-color 0.2s, color 0.2s, box-shadow 0.2s, opacity 0.2s; }
.photo-select-mark.checked { border-color: var(--danger); background: var(--danger); color: #fff; box-shadow: 0 0 10px rgba(255,71,87,0.5); }
.photo-select-mark svg { width: 14px; height: 14px; }

.photo-shine { position: absolute; inset: 0; border-radius: var(--radius); pointer-events: none; opacity: 0; transition: opacity 0.3s; }
.photo-card:hover .photo-shine { opacity: 1; }

/* 空状态 */
.empty { display: flex; flex-direction: column; align-items: center; justify-content: center; padding: 48px; width: 100%; min-height: 200px; }
.empty-icon { font-size: 40px; color: var(--text-muted); opacity: 0.3; margin-bottom: 8px; }
.empty-text { font-size: 13px; color: var(--text-muted); margin-bottom: 4px; }
.empty-hint { font-size: 11px; color: var(--text-muted); opacity: 0.6; text-align: center; }

/* 查看器 */
.viewer { position: fixed; inset: 0; background: rgba(0,0,0,0.96); display: flex; align-items: center; justify-content: center; z-index: 2000; transition: filter 0.4s var(--ease); animation: viewer-in 0.4s var(--ease); }
@keyframes viewer-in { from { opacity: 0; } to { opacity: 1; } }
.viewer.blurred { filter: blur(50px) brightness(0.2); }
.viewer-content { max-width: 90vw; max-height: 90vh; display: flex; flex-direction: column; gap: 12px; align-items: center; position: relative; }
.viewer-image { max-width: 90vw; max-height: 80vh; object-fit: contain; border-radius: var(--radius); box-shadow: 0 0 40px rgba(0,0,0,0.8), 0 0 1px rgba(0,212,255,0.2); transform-origin: center center; transition: transform 0.12s ease-out; animation: photo-in 0.6s var(--ease); user-select: none; -webkit-user-drag: none; }
.viewer-image.dragging { transition: none; }
@keyframes photo-in { from { opacity: 0; } to { opacity: 1; } }
.viewer-info { display: flex; align-items: center; gap: 16px; }
.viewer-name { font-size: 12px; color: var(--text-primary); font-family: var(--font); }
.viewer-hint { font-size: 10px; color: var(--text-muted); font-family: var(--font); letter-spacing: 1px; }

/* 动画关键帧（被导出对话框等复用） */
@keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
@keyframes dialog-in { from { opacity: 0; transform: scale(0.95) translateY(10px); } to { opacity: 1; transform: scale(1) translateY(0); } }

/* ===== 导出对话框 ===== */
.export-dialog-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.84); display: flex; align-items: center; justify-content: center; z-index: 4000; animation: fade-in 0.2s var(--ease); }
.export-dialog { width: 640px; max-height: 88vh; display: flex; flex-direction: column; border-radius: var(--radius); animation: dialog-in 0.3s var(--ease); overflow: hidden; }
.ed-header { display: flex; align-items: center; justify-content: space-between; padding: 16px 20px; border-bottom: 1px solid var(--border-glass); flex-shrink: 0; }
.ed-title-row { display: flex; align-items: center; gap: 8px; }
.ed-icon { width: 18px; height: 18px; color: var(--accent); }
.ed-title { font-size: 14px; color: var(--text-primary); letter-spacing: 1px; }
.ed-close { width: 28px; height: 28px; border: none; background: transparent; color: var(--text-muted); font-size: 18px; cursor: pointer; transition: color 0.2s; border-radius: var(--radius-sm); }
.ed-close:hover { color: var(--danger); }
.ed-close:disabled { opacity: 0.3; cursor: not-allowed; }

.ed-body { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 16px; }

.ed-section { display: flex; flex-direction: column; gap: 10px; }
.ed-section-header { display: flex; align-items: center; justify-content: space-between; }
.ed-section-title { font-size: 12px; color: var(--text-secondary); letter-spacing: 1px; text-transform: uppercase; font-family: var(--font); }
.ed-section-actions { display: flex; align-items: center; gap: 6px; }
.ed-selected-count { font-size: 11px; color: var(--accent); font-family: var(--font); }
.ed-mini-btn { display: flex; align-items: center; gap: 3px; padding: 4px 8px; font-size: 10px; border: 1px solid var(--border-glass); border-radius: var(--radius-sm); background: transparent; color: var(--text-muted); cursor: pointer; transition: all 0.2s; font-family: var(--font); white-space: nowrap; }
.ed-mini-btn:hover { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.06); }
.ed-mini-btn:disabled { opacity: 0.4; cursor: not-allowed; }

/* 照片选择网格 — 固定行高防止大量照片时被压缩成"能量条"，默认显示两行 */
.ed-photo-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); grid-auto-rows: 108px; gap: 8px; max-height: 224px; min-height: 224px; overflow-y: auto; padding-right: 4px; flex-shrink: 0; }
.ed-photo-item { position: relative; border: 2px solid transparent; border-radius: var(--radius-sm); overflow: hidden; cursor: pointer; transition: all 0.2s; background: rgba(0,0,0,0.3); min-height: 108px; }
.ed-photo-item:hover { border-color: rgba(0,212,255,0.2); }
.ed-photo-item.selected { border-color: var(--accent); box-shadow: 0 0 12px rgba(0,212,255,0.3); }
.ed-photo-thumb { width: 100%; height: 70px; background-size: cover; background-position: center; }
.ed-photo-name { display: block; font-size: 9px; color: var(--text-secondary); font-family: var(--font); padding: 3px 5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ed-photo-size { display: block; font-size: 8px; color: var(--text-muted); padding: 0 5px 4px; }

/* 令牌显示 */
.ed-token-display { display: flex; align-items: center; gap: 8px; padding: 12px 14px; background: rgba(0,0,0,0.4); border: 1px solid rgba(0,212,255,0.15); border-radius: var(--radius); }
.ed-token-code { flex: 1; font-family: var(--font-mono); font-size: 12px; color: var(--accent); word-break: break-all; letter-spacing: 1px; line-height: 1.6; cursor: pointer; transition: color 0.2s; }
.ed-token-code:hover { color: #00ffaa; }
.ed-token-actions { display: flex; gap: 6px; flex-shrink: 0; }
.ed-token-btn { display: flex; align-items: center; justify-content: center; width: 26px; height: 26px; padding: 0; border: 1px solid var(--border-glass); border-radius: var(--radius-sm); background: transparent; color: var(--text-muted); cursor: pointer; transition: all 0.2s var(--ease); }
.ed-token-btn svg { width: 12px; height: 12px; transition: transform 0.4s var(--ease); }
.ed-token-btn:hover:not(:disabled) { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.06); }
.ed-token-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.ed-token-btn--spin:hover:not(:disabled) svg { transform: rotate(180deg); }
.ed-token-btn.is-copied { color: #00ffaa; border-color: rgba(0,255,170,0.4); background: rgba(0,255,170,0.08); }
.ed-token-info { display: flex; flex-direction: column; gap: 6px; }
.ed-token-strength { display: flex; align-items: center; gap: 8px; font-size: 10px; color: var(--text-muted); }
.ed-strength-bar { flex: 1; height: 3px; background: rgba(255,255,255,0.05); border-radius: 2px; overflow: hidden; max-width: 200px; }
.ed-strength-fill { height: 100%; background: linear-gradient(90deg, var(--accent), #00ffaa); border-radius: 2px; }
.ed-strength-label { color: var(--success); font-family: var(--font); font-weight: 600; }
.ed-token-hint { font-size: 10px; color: var(--text-muted); opacity: 0.7; line-height: 1.5; }

/* 导出选项 */
.ed-format-opts { display: flex; gap: 10px; }
.ed-radio { flex: 1; display: flex; align-items: flex-start; gap: 8px; padding: 10px 12px; border: 1px solid var(--border-glass); border-radius: var(--radius); cursor: pointer; transition: all 0.2s; }
.ed-radio:hover { border-color: rgba(0,212,255,0.2); }
.ed-radio.active { border-color: var(--accent); background: rgba(0,212,255,0.05); }
.ed-radio input { margin-top: 2px; accent-color: var(--accent); }
.ed-radio-content { display: flex; flex-direction: column; gap: 2px; }
.ed-radio-title { font-size: 12px; color: var(--text-primary); }
.ed-radio-desc { font-size: 10px; color: var(--text-muted); }

.ed-path-row { display: flex; align-items: center; gap: 8px; }
.ed-path-label { font-size: 11px; color: var(--text-secondary); white-space: nowrap; }
.ed-path-input { flex: 1; padding: 8px 10px; background: rgba(0,0,0,0.3); border: 1px solid var(--border-glass); border-radius: var(--radius-sm); color: var(--text-secondary); font-family: var(--font-mono); font-size: 11px; outline: none; cursor: pointer; }
.ed-path-input:focus { border-color: var(--accent); }
.ed-browse-btn { white-space: nowrap; }

.ed-summary { display: flex; gap: 16px; padding: 10px 12px; background: rgba(0,0,0,0.2); border-radius: var(--radius-sm); }
.ed-summary-item { display: flex; flex-direction: column; gap: 2px; }
.ed-summary-label { font-size: 9px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }
.ed-summary-value { font-size: 12px; color: var(--accent); font-family: var(--font); }

.ed-progress { padding: 8px 0; }
.ed-footer { display: flex; justify-content: flex-end; gap: 8px; padding: 14px 20px; border-top: 1px solid var(--border-glass); flex-shrink: 0; }
.ed-confirm { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.08); padding: 6px 16px; }
.ed-confirm:hover:not(:disabled) { background: rgba(0,212,255,0.15); }
.ed-confirm:disabled { opacity: 0.4; cursor: not-allowed; }

/* 提示过渡动画（复用全局 .clip-toast） */
.toast-enter-active, .toast-leave-active { transition: all 0.3s var(--ease); }
.toast-enter-from, .toast-leave-to { opacity: 0; transform: translate(-50%, 10px); }

/* Toast 层级与变体（覆盖导出对话框 z-index:4000，不改全局 components.css） */
.clip-toast--over-dialog { z-index: 4500; }
.clip-toast--top { top: 24px; bottom: auto; }
.clip-toast--success { color: #00ffaa; }
.clip-toast--success .toast-dot { background: #00ffaa; }
.clip-toast--error { color: var(--danger); }
.clip-toast--error .toast-dot { background: var(--danger); }

/* ===== 解析对话框（外壳复用 CosmicOverlay + kv-* 全局样式，仅保留解析特有元素） ===== */
.parse-file-row { display: flex; gap: 8px; }
.parse-file-input { flex: 1; }
.parse-browse-btn { white-space: nowrap; }
.parse-token-input { width: 100%; color: var(--accent); font-family: var(--font-mono); }
.parse-result { display: flex; flex-direction: column; gap: 12px; margin-top: 16px; }
.parse-result-title { font-size: 12px; color: var(--accent); }
.parse-preview-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(80px, 1fr)); gap: 8px; max-height: 200px; overflow-y: auto; }
.parse-preview-item { display: flex; flex-direction: column; gap: 4px; align-items: center; }
.parse-preview-thumb { width: 70px; height: 70px; border-radius: 6px; background-size: cover; background-position: center; background-color: rgba(0,0,0,0.3); }
.parse-preview-name { font-size: 10px; color: var(--text-muted); text-align: center; word-break: break-all; }
</style>
