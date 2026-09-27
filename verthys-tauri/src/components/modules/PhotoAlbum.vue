<!--
  PhotoAlbum.vue — 拾光模块入口文件

  入口文件单一职责（不可突破红线）：
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
        <button class="btn btn-sm export-top-btn" @click="openExportDialog" :disabled="photos.length === 0 || albumBusy" v-tip="'导出加密照片'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
        </button>
        <button class="btn btn-sm export-top-btn" @click="openParseDialog" :disabled="albumBusy" v-tip="'解析加密文件并导入'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
        </button>
        <button
          class="btn btn-sm import-top-btn"
          :disabled="albumBusy"
          @click="onImport"
          v-tip="importing ? `加密中…${importProgress}%` : '导入照片'"
        >
          <!-- 加号：添加照片入库语义；导入中图标位切换为旋转指示器（进度由悬浮提示与中枢覆盖层承担） -->
          <svg v-if="!importing" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <line x1="12" y1="5" x2="12" y2="19"/>
            <line x1="5" y1="12" x2="19" y2="12"/>
          </svg>
          <span v-else class="import-spinner"></span>
        </button>
        <!-- 重打包入口（仅写入布局开关开启时出现）：后台迁移旧布局照片 -->
        <button
          v-if="repackAvailable && !repackRunning"
          class="btn btn-sm repack-top-btn"
          @click="startRepack"
          v-tip="'迁移旧布局照片（后台任务，可取消）'"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5">
            <polyline points="23 4 23 10 17 10"/>
            <polyline points="1 20 1 14 7 14"/>
            <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>
          </svg>
        </button>
        <button class="btn btn-sm del-top-btn" :class="{ active: selectMode }" :disabled="albumBusy && !selectMode" @click="onDeleteBtn" v-tip="selectMode ? '取消选择' : '选择删除'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
        </button>
      </div>
    </div>

    <!-- 加载状态横幅：扫描失败/降级/密钥失效/解密失败/解密暂停必须可见，
         并给出可执行动作（重试 / 继续解密）；禁止把失败折叠成"暂无照片"的空态。
         置于滚动容器之外，保证滚动时始终可见 -->
    <div v-if="loadError || decryptPaused || failedCount > 0" class="photo-load-banner glass">
      <span class="toast-dot"></span>
      <span class="photo-load-text">{{ bannerText }}</span>
      <button class="photo-load-retry" type="button" @click="bannerAction">{{ bannerActionText }}</button>
    </div>

    <!-- 重打包进度（后台任务运行中）：与加载横幅同区，提供取消入口 -->
    <div v-if="repackRunning && repackState" class="photo-load-banner glass">
      <span class="toast-dot"></span>
      <span class="photo-load-text">{{ repackState.message }}</span>
      <button class="photo-load-retry" type="button" @click="cancelRepack">取消迁移</button>
    </div>

    <!-- Masonry 瀑布流（滚动容器与列布局分离，确保滚轮垂直滚动正常） -->
    <div class="masonry-scroll" ref="scrollRef" @scroll="onScroll">
      <!-- 导入进度悬浮覆盖层（统一组件）：悬浮照片区中央，不挤压网格布局 -->
      <ImportProgressOverlay
        :visible="importing"
        :percent="importProgress"
        :message="importStatus"
        :elapsed="importElapsed"
        :show-meta="true"
      />

      <!-- 非阻塞加载：无底板居中展示，加载完成自动消失。
           加载过程不打断浏览（无阶段进度卡）；失败由通用错误提示（toast）
           与顶部状态横幅（重试入口）承载。 -->
      <CosmicLoading :show="photosLoading && photos.length === 0" text="正在加载照片列表…" />

      <!-- 虚拟滚动容器（相册列表强制采用虚拟滚动）：
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
            </div>
            <div class="photo-shine"></div>
          </div>
        </div>
      </div>

      <CosmicEmpty v-if="!photosLoading && photos.length === 0 && !loadError" text="暂无照片" hint="点击「导入照片」添加 · 自动 XChaCha20 加密" />
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
          <!-- 原图准备阶段反馈：读取密文块 / 解密中（真实阶段） -->
          <span v-if="viewerLoading" class="viewer-status">{{ viewerProgressMsg }}</span>
        </div>
      </div>
    </div>

    <!-- 导出对话框：两栏工作台（左选片 / 右配置；计数融入头部、摘要融入底栏） -->
    <div v-if="showExportDialog" class="export-dialog-overlay" @click.self="closeExportDialog">
      <div class="export-dialog glass">
        <div class="ed-header">
          <span class="ed-title">导出加密照片</span>
          <div class="ed-header-right">
            <span class="ed-count">已选 <b>{{ exportSelectedIds.size }}</b> / {{ photos.length }}</span>
            <button class="ed-close" @click="closeExportDialog" :disabled="exporting">×</button>
          </div>
        </div>

        <div class="ed-body">
          <!-- 左栏：选片（工具条 + 自适应网格，滚动收敛在栏内） -->
          <div class="ed-pane ed-pane--gallery">
            <div class="ed-gallery-bar">
              <button class="ed-mini-btn" @click="selectAllPhotos" :disabled="exporting">全选</button>
              <button class="ed-mini-btn" @click="deselectAllPhotos" :disabled="exporting">清空</button>
            </div>
            <div class="ed-photo-grid">
              <div
                v-for="ph in photos"
                :key="ph.id"
                class="ed-photo-item"
                :class="{ selected: exportSelectedIds.has(ph.id) }"
                @click="togglePhotoSelect(ph.id)"
                v-tip="`${ph.name} · ${ph.size}`"
              >
                <div class="ed-photo-thumb" :style="{ backgroundImage: ph.thumb }"></div>
                <span class="ed-photo-name">{{ ph.name }}</span>
              </div>
            </div>
          </div>

          <!-- 右栏：配置（格式 / 令牌 / 保存位置） -->
          <div class="ed-pane ed-pane--config">
            <div class="ed-group">
              <span class="ed-group-label">格式</span>
              <div class="ed-seg">
                <label class="ed-seg-item" :class="{ active: exportFormat === 'single' }">
                  <input type="radio" v-model="exportFormat" value="single" :disabled="exporting" />
                  <span>单文件</span>
                </label>
                <label class="ed-seg-item" :class="{ active: exportFormat === 'multiple' }">
                  <input type="radio" v-model="exportFormat" value="multiple" :disabled="exporting" />
                  <span>多文件</span>
                </label>
                <label class="ed-seg-item" :class="{ active: exportFormat === 'png' }">
                  <input type="radio" v-model="exportFormat" value="png" :disabled="exporting" />
                  <span>PNG</span>
                </label>
              </div>
              <p class="ed-hint">{{ exportFormat === 'single' ? '全部照片打包为一个 .venc 文件' : exportFormat === 'multiple' ? '每张照片导出为独立 .venc 文件' : '导出为 .png 图片，其他格式自动转码' }}</p>
            </div>

            <!-- 令牌（PNG 明文导出不需要） -->
            <div v-if="exportFormat !== 'png'" class="ed-group">
              <span class="ed-group-label">令牌</span>
              <div class="ed-token-display">
                <input
                  class="ed-token-code"
                  v-model="exportToken"
                  :disabled="exporting"
                  spellcheck="false"
                  autocomplete="off"
                  aria-label="导出令牌（可编辑自定义）"
                  v-tip="'可直接编辑为自定义令牌'"
                />
                <div class="ed-token-actions">
                  <button class="ed-token-btn ed-token-btn--spin" @click="regenerateExportToken" :disabled="exporting" v-tip="'重新生成'">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
                  </button>
                  <button class="ed-token-btn" :class="{ 'is-copied': tokenCopied }" @click="copyExportToken" v-tip="'复制'">
                    <svg v-if="tokenCopied" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                    <svg v-else viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                  </button>
                </div>
              </div>
              <p class="ed-hint">256-bit · 无此令牌无法解密导出文件</p>
            </div>

            <div class="ed-group">
              <span class="ed-group-label">保存到</span>
              <button class="ed-path" type="button" @click="chooseExportPath" :disabled="exporting">
                <span class="ed-path-text">{{ exportPath }}</span>
                <svg class="ed-path-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>
              </button>
            </div>
          </div>
        </div>

        <!-- 进度线：底栏顶缘细线，导出中点亮 -->
        <div class="ed-progress-line" :class="{ live: exporting }">
          <i :style="{ width: exporting ? exportProgress + '%' : '0%' }"></i>
        </div>

        <div class="ed-footer">
          <span class="ed-summary-line">
            <template v-if="exporting">{{ exportStatus }}</template>
            <template v-else-if="!exportPath">尚未选择保存位置</template>
            <template v-else>{{ exportSelectedIds.size }} 张 · {{ exportFormat === 'single' ? '单文件' : exportFormat === 'multiple' ? '多文件' : 'PNG' }} · {{ exportFormat === 'png' ? '明文' : 'AES-256' }}</template>
          </span>
          <div class="ed-footer-actions">
            <button class="btn btn-sm" @click="closeExportDialog" :disabled="exporting">取消</button>
            <button
              class="btn btn-sm ed-confirm"
              @click="doExport"
              :disabled="exporting || exportSelectedIds.size === 0 || !exportPath"
            >
              {{ exporting ? '导出中…' : '开始导出' }}
            </button>
          </div>
        </div>
      </div>
    </div>

    <!-- 解析对话框（复用子密钥验证窗口 CosmicOverlay + kv-* 样式） -->
    <!-- 单一 v-if/v-else-if 链：互斥状态机，避免多链导致元素同时显示
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
        <div v-if="parsedUndecryptable > 0" class="parse-undecryptable-hint">
          {{ parsedUndecryptable }} 张无法用当前拾光密钥解密，将不会被导入
        </div>
        <!-- 空数据记录单独归因：容器内本就不含内容块，与"密钥不匹配"是两回事 -->
        <div v-if="parsedEmpty > 0" class="parse-undecryptable-hint">
          {{ parsedEmpty }} 张为空数据记录（无图像块），将不会被导入
        </div>
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
          <input class="kv-input parse-file-input" :value="parseFileName" readonly placeholder="请选择 .venc 文件" />
          <button class="btn btn-sm parse-browse-btn" @click="chooseParseFile" v-tip="'打开文件'">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m6 14 1.45-2.9A2 2 0 0 1 9.24 10H20a2 2 0 0 1 1.94 2.5l-1.55 6a2 2 0 0 1-1.94 1.5H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h3.93a2 2 0 0 1 1.66.9l.82 1.2a2 2 0 0 0 1.66.9H18a2 2 0 0 1 2 2v2"/></svg>
          </button>
        </div>
        <div style="height: 12px;"></div>
        <input class="kv-input parse-token-input" v-model="parseToken" placeholder="请输入密钥" />
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

    <!-- 选择模式操作栏（悬浮层）：绝对定位悬浮照片区底部中央，不占据文档流、不挤压网格 -->
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
          @click="onDeleteSelected"
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          删除选中{{ selectedPhotoIds.size > 0 ? ` (${selectedPhotoIds.size})` : '' }}
        </button>
      </div>
    </div>

    <!-- 删除二次确认弹窗（复用全局 ConfirmDelete，与存签/枢钥/清藏的删除确认一致） -->
    <ConfirmDelete
      :show="showDeleteConfirm"
      :item-name="`已选 ${deleteConfirmCount} 张照片`"
      :desc="`即将删除已选 ${deleteConfirmCount} 张照片，此操作不可撤销，删除后数据将永久丢失`"
      @confirm="confirmDelete"
      @cancel="cancelDeleteConfirm"
    />
  </div>
</template>

<script setup lang="ts">
/**
 *   1. 装配 composable（applyDependencies）
 *   2. 调度生命周期（initLifecycle / cleanupLifecycle）
 *   3. 安全前置校验闸门（isModuleReady + ensurePhotoKey）
 *   4. 渲染模板
 *
 * 业务逻辑零侵入：所有加密/解密、verthys 读写、数据处理、交互逻辑均下沉至
 * composables/photo-album/ 分层目录，入口仅通过依赖注入装配。
 */
import { onMounted, onUnmounted, computed, watch, defineAsyncComponent } from "vue";
import { isModuleReady } from "../../lib/keyManager";
import { tryGc } from "../../utils/gc";
import CosmicLoading from "../common/cosmic/CosmicLoading.vue";
import CosmicEmpty from "../common/cosmic/CosmicEmpty.vue";
import ConfirmDelete from "../common/verthys-ui/ConfirmDelete.vue";
// 大型弹窗组件级懒加载（遵循项目硬约束：大型弹窗使用 defineAsyncComponent）
const CosmicOverlay = defineAsyncComponent(() => import("../common/cosmic/CosmicOverlay.vue"));
// 量子能量导流通道进度条（全局统一进度条组件，替代已删除的 QuantumProgressBar）
const QuantumProgressFlow = defineAsyncComponent(() => import("../common/cosmic/QuantumProgressFlow.vue"));
// 导入进度悬浮覆盖层（全局统一遮挡层，悬浮内容区中央、不挤压布局）
const ImportProgressOverlay = defineAsyncComponent(() => import("../common/cosmic/ImportProgressOverlay.vue"));

/* ===== 分层 composable 装配（依赖加载调度器） ===== */
import { usePhotoToast } from "../../composables/photo-album/usePhotoToast";
import { usePhotoData } from "../../composables/photo-album/usePhotoData";
import { usePhotoImport } from "../../composables/photo-album/usePhotoImport";
import { usePhotoExport } from "../../composables/photo-album/usePhotoExport";
import { usePhotoViewer } from "../../composables/photo-album/usePhotoViewer";
import { usePhotoParse } from "../../composables/photo-album/usePhotoParse";
import { usePhotoRepack } from "../../composables/photo-album/usePhotoRepack";
import { usePhotoDelete } from "../../composables/photo-album/usePhotoDelete";
import { usePhotoPrivacy } from "../../composables/photo-album/usePhotoPrivacy";
import { usePhotoInteraction } from "../../composables/photo-album/usePhotoInteraction";
import { useModuleDialogGuard } from "../../composables/useModuleDialogGuard";
import { resolveChunkSet } from "../../composables/photo-album/chunk-refs";

/* ---------- 1. Toast 反馈中心（最先装配，后续 composable 依赖其 showError 等） ---------- */
const {
  errorMsg, toastMsg, exportDoneToast, copiedToast,
  showError, showToast, showExportDone, showCopied,
} = usePhotoToast();

/* ---------- 2. 核心数据层（提供 photos / photoKey / isTauri / 虚拟滚动 / 按需解密） ---------- */
const {
  photos, photoKey, isTauri, photosLoading, animationDone,
  loadError, failedCount, decryptPaused,
  scrollRef, scrollTop, viewportHeight, containerWidth, columns,
  itemWidth, rowHeight, totalRows, totalHeight, visiblePhotos,
  onScroll, updateLayout, resizeObserver,
  initVirtualScroll, destroyVirtualScroll,
  decryptPhotoMeta, loadPhotos, retryLoad, resumeLoad, releaseThumbUrls, ensurePhotoKey,
  cancelPendingDecrypt,
} = usePhotoData();

/* ===== 加载状态的展示派生（表现层，无业务判断） ===== */
/** 相册内重操作统一忙碌信号：任一在途即禁用全部并发入口。
 *  互斥第一道防线必须在 UI（前端先拦），后端拒绝（导入管线重入守卫）仅作兜底；
 *  解析导入期间若不拦，用户会付出"选文件/加密"成本后才被拒绝。 */
const albumBusy = computed(() =>
  importing.value || parsing.value || importingParsed.value || exporting.value || repackRunning.value,
);
/** 加载失败/降级：以通用错误提示（toast）呈现（顶部横幅保留错误文案与重试入口） */
watch(loadError, (v) => {
  if (v) showError(v);
});

/** 状态横幅文案：暂停 > 错误 > 失败计数（越需要用户处理越靠前） */
const bannerText = computed(() => {
  if (decryptPaused.value) return "已暂停解密：可视区缩略图不再自动补齐";
  if (loadError.value) return loadError.value;
  return `已加载 ${photos.value.length - failedCount.value} 张，${failedCount.value} 张解密失败`;
});
/** 横幅动作：暂停态给"继续解密"，其余给"重试" */
const bannerAction = computed(() => (decryptPaused.value ? resumeLoad : retryLoad));
const bannerActionText = computed(() => (decryptPaused.value ? "继续解密" : "重试"));

/* ---------- 3. 查看器层（依赖 usePhotoData 的 photos/photoKey/decryptPhotoMeta） ---------- */
const {
  viewer, viewerSrc, viewerName, viewerBlurred, viewerScale,
  viewerOffsetX, viewerOffsetY, viewerDragging, viewerLoading, viewerProgressMsg,
  onView, closeViewer, onViewerWheel, onViewerMouseDown, onViewerDoubleClick,
  onBlur, onFocus,
  cleanup: cleanupViewer,
} = usePhotoViewer({
  photos, photoKey, isTauri, ensurePhotoKey, decryptPhotoMeta, showError,
});

/* ---------- 4. 导入层 ---------- */
const {
  importing, importProgress, importStatus,
  /* Comprehensive_optimization：新增耗时与 ETA（供 QuantumProgressFlow 使用） */
  importElapsed, importEta,
  onImport,
  /* 卸载时取消进行中的导入（守护流水线：中止投喂并保留 WAL 续传） */
  abortImport,
  /* Parsed Import：导出 getPipeline 供 usePhotoParse 复用同一流水线实例 */
  getPipeline,
} = usePhotoImport({
  photos, photoKey, isTauri, ensurePhotoKey, showError, showToast,
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
  showParseDialog, parseFileName, parseFileData, parseToken, parsing, parsedPhotos, parsedUndecryptable,
  parsedEmpty,
  // 感知：进度条状态（复用中枢初始化窗口进度条样式，非量子动画）
  fileLoading, fileLoadingPercent, fileLoadingMsg,
  parsingPercent, parsingMsg,
  /* Parsed Import：对话框内导入进度条状态（复用 QuantumProgressFlow 组件） */
  importingParsed,
  openParseDialog, closeParseDialog, chooseParseFile, doParse, importParsedPhotos,
} = usePhotoParse({
  photos, photoKey, isTauri, ensurePhotoKey, showError, showToast,
  /* Parsed Import：复用 usePhotoImport 的流水线实例 + 导入状态 refs
     （对话框内复用 QuantumProgressFlow，导入进度实时反馈，UI 不卡死） */
  getPipeline, importing, importProgress, importStatus, importElapsed, importEta,
});

/* ---------- 6b. 重打包层（后台迁移旧布局照片；复用导入流水线写入链路） ---------- */
const {
  repackAvailable, repackRunning, repackState, startRepack, cancelRepack,
} = usePhotoRepack({
  photos, photoKey, isTauri, getPipeline, showToast, showError,
});

/* ---------- 7. 删除层（依赖 usePhotoViewer 的 onView 用于非选择模式下的照片点击） ---------- */
const {
  selectMode, selectedPhotoIds, allSelected,
  toggleSelectAll, cancelSelectMode, onDelete, onDeleteBtn, onDeleteSelected, onPhotoClick,
  showDeleteConfirm, deleteConfirmCount, confirmDelete, cancelDeleteConfirm,
} = usePhotoDelete({
  photos, isTauri, onView, showError, showToast,
  // 占位项删除兜底：meta 未解密时强制解密，补齐 chunk 级联与去重锁释放
  resolveMeta: async (metaId: number) => (await decryptPhotoMeta(metaId))?.meta ?? null,
  // 瘦身布局的逐块 ID 在块集记录内：删除级联前先解析（失败退化为内联引用）
  resolveChunkIds: async (metaId: number, meta) => {
    const set = await resolveChunkSet(meta, photoKey.value, `删除 #${metaId}`);
    return set?.ids ?? [];
  },
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

  // 虚拟滚动布局初始化收敛至数据层（initVirtualScroll 内部完成 updateLayout + ResizeObserver 注册）
  initVirtualScroll();

  // 首批照片入场动画播完后禁用，避免虚拟滚动时新进入可视区项重播动画导致闪烁
  setTimeout(() => { animationDone.value = true; }, 1500);

  // 安全前置校验闸门：模块密钥已由 MainView 登录时缓存到 keyManager 会话，直接读取
  if (isTauri) {
    if (isModuleReady("photo") && ensurePhotoKey()) {
      loadPhotos();
    } else {
      // 保护关闭或密钥已失效：给出可见原因，避免只剩"暂无照片"的空态
      loadError.value = "模块密钥不可用（模块保护未开启或密钥已失效），请从安全管理进入拾光";
    }
  } else {
    // 浏览器模式：使用占位密钥（仅用于本地演示，不涉及真实加密）
    photoKey.value = "browser_demo_key";
  }
};

/**
 * 清理生命周期：
 *   - 移除窗口事件监听
 *   - 取消进行中的导入（中止投喂 + WAL 续传收尾）
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

  // 取消进行中的导入：中止投喂新文件，已提交批次收尾并保留 WAL 续传
  abortImport();

  // 取消进行中的重打包：当前一张收尾后停止（源记录不会半途删除，可再次续跑）
  cancelRepack();

  // 取消 rafThrottle 未触发的回调
  onScroll.cancel();
  cancelInteraction();

  // 取消去抖中未触发的可视区解密批次（防止卸载后写状态）
  cancelPendingDecrypt();

  // 销毁虚拟滚动（释放 ResizeObserver）
  destroyVirtualScroll();

  // 释放查看器 Blob URL
  cleanupViewer();

  // 关闭隐私模式（fire-and-forget，不阻塞卸载）
  cleanupPrivacy();

  // 释放浏览器模式的 Blob URL
  for (const ph of photos.value) {
    if (ph.blobUrl) URL.revokeObjectURL(ph.blobUrl);
  }

  // 释放缩略图 Blob URL（数据层统一遍历，与生成点成对）
  releaseThumbUrls();

  // 项12：清空照片数组释放引用 + 主动触发 V8 Major GC
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
  // 删除确认弹窗随模块切换一并关闭，杜绝残留遮挡
  showDeleteConfirm.value = false;
});
</script>

<style scoped>
.photo-album { width: 100%; height: 100%; display: flex; flex-direction: column; gap: 14px; overflow: hidden; position: relative; }

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

/* 顶部纯图标按钮（导出/解析/导入照片）：与 .del-top-btn 同尺寸 32×32，无文字标签，语义由 v-tip 悬浮提示承担 */
.export-top-btn, .import-top-btn { display: flex; align-items: center; justify-content: center; width: 32px; height: 32px; padding: 0; }
.export-top-btn svg, .import-top-btn svg { width: 14px; height: 14px; }
/* 顶部纯图标按钮禁用态：视觉降级 + not-allowed 光标；:hover 同规则覆盖，
   避免禁用按钮在悬浮时仍出现提亮反馈（误导为可点击） */
.export-top-btn:disabled, .import-top-btn:disabled, .del-top-btn:disabled,
.export-top-btn:disabled:hover, .import-top-btn:disabled:hover, .del-top-btn:disabled:hover {
  opacity: 0.35; cursor: not-allowed;
  border-color: var(--border-glass);
  background: rgba(var(--bg-tertiary-rgb), 0.62);
  color: var(--text-muted);
}
/* 重打包入口：与其它顶栏图标按钮同尺寸；仅写入布局开关开启时出现 */
.repack-top-btn { display: flex; align-items: center; justify-content: center; width: 32px; height: 32px; padding: 0; color: var(--text-muted); }
.repack-top-btn svg { width: 14px; height: 14px; }
.repack-top-btn:hover { color: var(--accent); border-color: rgba(var(--accent-rgb), 0.3); background: rgba(var(--accent-rgb), 0.06); }
/* 导入中旋转指示器（仅导入照片按钮在加密过程中显示，替换静态图标） */
.import-spinner { width: 13px; height: 13px; border: 1.5px solid var(--accent); border-top-color: transparent; border-radius: 50%; animation: import-top-spin 0.7s linear infinite; }
@keyframes import-top-spin { to { transform: rotate(360deg); } }
.del-top-btn { display: flex; align-items: center; justify-content: center; width: 32px; height: 32px; padding: 0; color: var(--text-muted); transition: all 0.2s; }
.del-top-btn svg { width: 14px; height: 14px; }
.del-top-btn:hover { color: var(--danger); border-color: rgba(255,71,87,0.3); background: rgba(255,71,87,0.06); }
.del-top-btn.active { color: var(--danger); border-color: rgba(255,71,87,0.4); background: rgba(255,71,87,0.1); }

/* 加载状态横幅：告知失败/降级原因并提供重试；点击态光标与反馈明确，无阴影 */
.photo-load-banner {
  display: flex; align-items: center; gap: 8px; flex: 0 0 auto;
  margin: 0 4px; padding: 8px 14px;
  font-size: 12px; color: var(--text-muted); font-family: var(--font);
  position: relative; z-index: 2;
}
.photo-load-banner .toast-dot { --mark-c: var(--accent); }
.photo-load-text { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.photo-load-retry {
  flex: 0 0 auto; padding: 4px 12px; font-size: 12px; font-family: var(--font);
  color: var(--accent); background: transparent; border: 1px solid var(--border-glass);
  border-radius: var(--radius); cursor: pointer;
  transition: color 0.2s var(--ease), border-color 0.2s var(--ease), background 0.2s var(--ease);
}
.photo-load-retry:hover { background: rgba(var(--accent-rgb), 0.08); border-color: rgba(var(--accent-rgb), 0.35); }
.photo-load-retry:active { background: rgba(var(--accent-rgb), 0.14); }
.photo-load-retry:focus-visible { outline: 1px solid rgba(var(--accent-rgb), 0.55); outline-offset: 2px; }
.plus { font-weight: 300; }

/* 导入进度 */
.import-progress { display: flex; align-items: center; gap: 12px; padding: 8px 16px; flex-shrink: 0; }
.progress-bar { flex: 1; height: 3px; background: rgba(255,255,255,0.05); border-radius: 2px; overflow: hidden; }
.progress-fill { height: 100%; background: linear-gradient(90deg, var(--accent), #b46cff); transition: width 0.3s var(--ease); border-radius: 2px; }
.progress-text { font-size: 11px; color: var(--text-secondary); font-family: var(--font); white-space: nowrap; }

/* 选择模式操作栏：悬浮层——绝对定位在照片区底部中央，脱离文档流不挤压网格。
   动画仅 opacity/transform（合成器友好）；玻璃底 + 零阴影与模块整体语言一致 */
.select-bar { position: absolute; bottom: 14px; left: 50%; transform: translateX(-50%); z-index: 30; display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 8px 16px; max-width: calc(100% - 28px); animation: select-bar-enter 0.3s var(--ease) both; }
@keyframes select-bar-enter { from { opacity: 0; transform: translate(-50%, 10px); } to { opacity: 1; transform: translate(-50%, 0); } }
.select-bar-left { display: flex; align-items: center; gap: 12px; }
.select-bar-right { display: flex; align-items: center; gap: 8px; }
.select-all-btn { display: flex; align-items: center; gap: 4px; font-size: 11px; cursor: pointer; }
.select-all-btn svg { width: 13px; height: 13px; }
.select-all-btn:hover { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.06); }
.select-count { font-size: 11px; color: var(--text-secondary); font-family: var(--font); letter-spacing: 0.5px; white-space: nowrap; }
.select-count strong { color: var(--accent); font-weight: 600; }
.select-cancel-btn { font-size: 11px; color: var(--text-muted); cursor: pointer; }
.select-cancel-btn:hover { color: var(--text-primary); }
.select-delete-btn { display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--danger); border-color: rgba(255,71,87,0.3); background: rgba(255,71,87,0.06); cursor: pointer; }
.select-delete-btn svg { width: 13px; height: 13px; }
.select-delete-btn:hover:not(:disabled) { background: rgba(255,71,87,0.12); border-color: rgba(255,71,87,0.5); }
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
/* 虚拟滚动：绝对定位网格容器（不再使用 CSS grid，由 JS 精确计算每项 translate3d 定位）
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

/* 选择删除模式：仅红框选中。环形描边内嵌于缩略图内部渲染，不超出元素边界，
   滚动容器边缘处（首行顶部/首列两侧）的描边不会被 overflow 裁剪；
   选择态重置为全圆角，使描边跟随卡片四角圆弧（默认非对称圆角会造成
   方角描边被圆形裁剪切掉，形成边框缺口） */
.masonry-item.selected .photo-thumb {
  border-radius: var(--radius);
  box-shadow: inset 0 0 0 2px var(--danger);
}

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
/* 原图准备阶段反馈：与文件名同排，低调呈现真实阶段（读取数据块 / 解密中） */
.viewer-status { font-size: 11px; color: var(--accent); font-family: var(--font); letter-spacing: 0.5px; }
.viewer-hint { font-size: 10px; color: var(--text-muted); font-family: var(--font); letter-spacing: 1px; }

/* 动画关键帧（被导出对话框等复用） */
@keyframes fade-in { from { opacity: 0; } to { opacity: 1; } }
@keyframes dialog-in { from { opacity: 0; transform: scale(0.95) translateY(10px); } to { opacity: 1; transform: scale(1) translateY(0); } }

/* ===== 导出对话框：两栏工作台（左选片 / 右配置） ===== */
.export-dialog-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.84); display: flex; align-items: center; justify-content: center; z-index: 4000; animation: fade-in 0.2s var(--ease); }
.export-dialog { width: min(860px, calc(100vw - 48px)); height: min(560px, calc(100vh - 96px)); display: flex; flex-direction: column; border-radius: var(--radius); animation: dialog-in 0.3s var(--ease); overflow: hidden; }

/* 头部：标题 + 实时计数 + 关闭（计数常驻头部，滚动区不再重复） */
.ed-header { display: flex; align-items: center; justify-content: space-between; padding: 18px 22px 14px; flex-shrink: 0; }
.ed-title { font-size: 15px; color: var(--text-primary); font-weight: 500; letter-spacing: 2px; }
.ed-header-right { display: flex; align-items: center; gap: 16px; }
.ed-count { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); letter-spacing: 0.5px; }
.ed-count b { color: var(--accent); font-weight: 600; font-size: 13px; }
.ed-close { width: 28px; height: 28px; border: none; background: transparent; color: var(--text-muted); font-size: 18px; cursor: pointer; transition: color 0.2s; border-radius: var(--radius-sm); }
.ed-close:hover { color: var(--danger); }
.ed-close:disabled { opacity: 0.3; cursor: not-allowed; }

/* 主体：左选片（弹性）/ 右配置（固定栏 + 细分隔线）；单行 1fr 撑满固定窗高 */
.ed-body { flex: 1; min-height: 0; display: grid; grid-template-columns: minmax(0, 1fr) 296px; grid-template-rows: minmax(0, 1fr); }
.ed-pane { min-height: 0; }
.ed-pane--gallery { display: flex; flex-direction: column; padding: 0 18px 0 22px; }
.ed-pane--config { display: flex; flex-direction: column; gap: 20px; padding: 2px 22px 10px 20px; border-left: 1px solid var(--border-glass); overflow-y: auto; }

/* 选片工具条 */
.ed-gallery-bar { display: flex; gap: 8px; padding-bottom: 10px; flex-shrink: 0; }
.ed-mini-btn { display: flex; align-items: center; gap: 3px; padding: 4px 10px; font-size: 10px; border: 1px solid var(--border-glass); border-radius: var(--radius-sm); background: transparent; color: var(--text-muted); cursor: pointer; transition: color 0.2s var(--ease), border-color 0.2s var(--ease), background 0.2s var(--ease); font-family: var(--font); white-space: nowrap; }
.ed-mini-btn:hover:not(:disabled) { color: var(--accent); border-color: rgba(var(--accent-rgb), 0.3); background: rgba(var(--accent-rgb), 0.06); }
.ed-mini-btn:disabled { opacity: 0.4; cursor: not-allowed; }

/* 选片网格：填满左栏（固定窗口内滚动收敛在栏内）；选中态为蓝色描边 */
.ed-photo-grid { flex: 1; min-height: 0; overflow-y: auto; display: grid; grid-template-columns: repeat(auto-fill, minmax(92px, 1fr)); grid-auto-rows: 92px; gap: 8px; padding: 1px 2px 14px 1px; align-content: start; }
.ed-photo-item { position: relative; border-radius: var(--radius-sm); overflow: hidden; cursor: pointer; background: rgba(0,0,0,0.35); outline: 1px solid transparent; outline-offset: -1px; transition: outline-color 0.18s var(--ease); }
.ed-photo-item:hover { outline-color: rgba(var(--accent-rgb), 0.3); }
.ed-photo-item.selected { outline: 2px solid var(--accent); }
.ed-photo-thumb { position: absolute; inset: 0 0 18px 0; background-size: cover; background-position: center; }
.ed-photo-name { position: absolute; left: 0; right: 0; bottom: 0; height: 18px; line-height: 18px; padding: 0 6px; font-size: 9px; color: var(--text-secondary); background: rgba(0,0,0,0.55); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

/* 配置组：微标签 + 延伸细线（编辑式分组，替代大写下标题堆叠） */
.ed-group { display: flex; flex-direction: column; gap: 9px; }
.ed-group-label { display: flex; align-items: center; gap: 10px; font-size: 10px; letter-spacing: 2px; color: var(--text-muted); }
.ed-group-label::after { content: ""; flex: 1; height: 1px; background: linear-gradient(90deg, var(--border-glass), transparent); }
.ed-hint { margin: 0; font-size: 10px; line-height: 1.6; color: var(--text-muted); opacity: 0.75; }

/* 格式分段控件：与令牌 / 保存位置行同宽同高（40px 整行） */
.ed-seg { display: grid; grid-template-columns: repeat(3, 1fr); gap: 2px; height: 40px; padding: 2px; background: rgba(0,0,0,0.35); border: 1px solid var(--border-glass); border-radius: var(--radius); }
.ed-seg-item { position: relative; display: grid; place-items: center; border-radius: calc(var(--radius) - 3px); font-size: 11px; color: var(--text-muted); cursor: pointer; transition: color 0.18s var(--ease), background 0.18s var(--ease), box-shadow 0.18s var(--ease); }
.ed-seg-item input { position: absolute; opacity: 0; pointer-events: none; }
.ed-seg-item:hover { color: var(--text-secondary); }
.ed-seg-item.active { color: var(--accent); background: rgba(var(--accent-rgb), 0.1); box-shadow: inset 0 0 0 1px rgba(var(--accent-rgb), 0.28); }
/* 键盘聚焦反馈：input 视觉隐藏后仍需可见的焦点指示 */
.ed-seg-item:has(input:focus-visible) { box-shadow: inset 0 0 0 1px rgba(var(--accent-rgb), 0.55); color: var(--text-secondary); }
.ed-seg-item:has(input:disabled) { opacity: 0.45; cursor: not-allowed; }

/* 令牌：与「保存到」行同宽同高（40px 整行）的文本框 + 操作钮（复制态转对勾） */
.ed-token-display { display: flex; align-items: center; gap: 10px; height: 40px; padding: 0 12px; background: rgba(0,0,0,0.4); border: 1px solid rgba(var(--accent-rgb), 0.14); border-radius: var(--radius); }
/* 令牌输入：单行（超长省略）+ 可直接编辑为自定义令牌 */
.ed-token-code { flex: 1; min-width: 0; background: transparent; border: none; outline: none; padding: 0; font-family: var(--font-mono); font-size: 11px; color: var(--accent); letter-spacing: 0.8px; text-overflow: ellipsis; cursor: text; transition: color 0.2s var(--ease); }
.ed-token-code::selection { background: rgba(var(--accent-rgb), 0.3); }
.ed-token-code:hover:not(:disabled), .ed-token-code:focus { color: #00ffaa; }
.ed-token-code:disabled { color: var(--text-muted); cursor: not-allowed; }
.ed-token-actions { display: flex; gap: 6px; flex-shrink: 0; }
.ed-token-btn { display: flex; align-items: center; justify-content: center; width: 26px; height: 26px; padding: 0; border: 1px solid var(--border-glass); border-radius: var(--radius-sm); background: transparent; color: var(--text-muted); cursor: pointer; transition: color 0.2s var(--ease), border-color 0.2s var(--ease), background 0.2s var(--ease); }
.ed-token-btn svg { width: 12px; height: 12px; transition: transform 0.4s var(--ease); }
.ed-token-btn:hover:not(:disabled) { color: var(--accent); border-color: rgba(var(--accent-rgb), 0.3); background: rgba(var(--accent-rgb), 0.06); }
.ed-token-btn:disabled { opacity: 0.4; cursor: not-allowed; }
.ed-token-btn--spin:hover:not(:disabled) svg { transform: rotate(180deg); }
.ed-token-btn.is-copied { color: #00ffaa; border-color: rgba(0,255,170,0.4); background: rgba(0,255,170,0.08); }

/* 保存位置：整行可选（未选择时为空文本框，仅保留文件夹图标作选择入口）；
   与令牌行同宽同高（40px 整行） */
.ed-path { display: flex; align-items: center; gap: 10px; width: 100%; height: 40px; padding: 0 12px; border: 1px solid var(--border-glass); border-radius: var(--radius); background: rgba(0,0,0,0.3); cursor: pointer; transition: border-color 0.2s var(--ease), background 0.2s var(--ease); text-align: left; }
.ed-path:hover:not(:disabled) { border-color: rgba(var(--accent-rgb), 0.35); background: rgba(var(--accent-rgb), 0.04); }
.ed-path:disabled { opacity: 0.45; cursor: not-allowed; }
.ed-path-text { flex: 1; min-width: 0; font-family: var(--font-mono); font-size: 11px; color: var(--text-secondary); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ed-path-icon { width: 14px; height: 14px; color: var(--text-muted); flex-shrink: 0; transition: color 0.2s var(--ease); }
.ed-path:hover:not(:disabled) .ed-path-icon { color: var(--accent); }

/* 进度线：底栏顶缘 2px 细线（导出中点亮，替代独立进度条区块） */
.ed-progress-line { position: relative; height: 2px; flex-shrink: 0; background: rgba(255,255,255,0.04); }
.ed-progress-line i { position: absolute; inset: 0 auto 0 0; width: 0; background: linear-gradient(90deg, var(--accent), #00ffaa); transition: width 0.25s var(--ease); }
.ed-progress-line.live { background: rgba(var(--accent-rgb), 0.08); }

/* 底栏：单行摘要（并入原汇总三项）+ 动作 */
.ed-footer { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px 22px 16px; flex-shrink: 0; }
.ed-summary-line { font-size: 11px; color: var(--text-muted); font-family: var(--font-mono); letter-spacing: 0.5px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.ed-footer-actions { display: flex; gap: 10px; flex-shrink: 0; }
.ed-confirm { color: var(--accent); border-color: rgba(var(--accent-rgb), 0.3); background: rgba(var(--accent-rgb), 0.08); padding: 6px 16px; }
.ed-confirm:hover:not(:disabled) { background: rgba(var(--accent-rgb), 0.15); }
.ed-confirm:disabled { opacity: 0.4; cursor: not-allowed; }

/* 窄窗兜底：单列堆叠（配置栏移至网格下方） */
@media (max-width: 760px) {
  .ed-body { grid-template-columns: minmax(0, 1fr); grid-template-rows: minmax(0, 1fr) auto; }
  .ed-pane--config { border-left: none; border-top: 1px solid var(--border-glass); padding: 14px 22px 6px; }
}

/* 提示过渡动画（复用全局 .clip-toast） */
.toast-enter-active, .toast-leave-active { transition: all 0.3s var(--ease); }
.toast-enter-from, .toast-leave-to { opacity: 0; transform: translate(-50%, 10px); }

/* Toast 层级与变体（覆盖导出对话框 z-index:4000，不改全局 components.css） */
.clip-toast--over-dialog { z-index: 4500; }
.clip-toast--top { top: 24px; bottom: auto; }
.clip-toast--success { color: #00ffaa; }
.clip-toast--success .toast-dot { --mark-c: #00ffaa; }
.clip-toast--error { color: var(--danger); }
.clip-toast--error .toast-dot { --mark-c: var(--danger); }

/* ===== 解析对话框（外壳复用 CosmicOverlay + kv-* 全局样式，仅保留解析特有元素） ===== */
.parse-file-row { display: flex; gap: 8px; }
.parse-file-input { flex: 1; }
/* 打开文件图标钮：34px 正方形、透明底 + 保留方框边框
   （覆盖 .btn 基础底色与内边距），悬浮仅图标与边框提亮 */
.parse-browse-btn { display: flex; align-items: center; justify-content: center; width: 34px; height: 34px; padding: 0; background: transparent; flex-shrink: 0; }
.parse-browse-btn:hover { background: transparent; border-color: var(--border-hover); color: var(--accent); }
.parse-browse-btn svg { width: 15px; height: 15px; }
/* 密钥输入沿用全局字体（与全局输入一致，不再使用等宽体） */
.parse-token-input { width: 100%; color: var(--accent); }
.parse-result { display: flex; flex-direction: column; gap: 12px; margin-top: 16px; }
.parse-result-title { font-size: 12px; color: var(--accent); }
.parse-undecryptable-hint { font-size: 11px; color: var(--warning, #e6a23c); line-height: 1.5; }
.parse-preview-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(80px, 1fr)); gap: 8px; max-height: 200px; overflow-y: auto; }
.parse-preview-item { display: flex; flex-direction: column; gap: 4px; align-items: center; }
.parse-preview-thumb { width: 70px; height: 70px; border-radius: 6px; background-size: cover; background-position: center; background-color: rgba(0,0,0,0.3); }
.parse-preview-name { font-size: 10px; color: var(--text-muted); text-align: center; word-break: break-all; }
</style>
