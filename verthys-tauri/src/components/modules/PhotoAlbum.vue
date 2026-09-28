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
    - Toast 反馈：复用全局 composables/useToastCenter（渲染归 ToastLayer，最高层）
    - usePhotoData         核心数据层（列表/虚拟滚动/按需解密/加载）
    - usePhotoImport       导入层（文件选择/加密入库）
    - usePhotoExport       导出层（对话框/三种格式导出）
    - usePhotoViewer       查看器层（内存预览/缩放）
    - usePhotoParse        解析层（.venc 解密/导入）
    - usePhotoDelete       删除层（单删/批删/选择模式）
    -（卡片指针光晕复用共享 composables/useCardShine —— 与存签/枢钥/钥域同一实现）
    - useModuleDialogGuard 弹窗清理守卫（页面覆盖根治）

  防截屏保护不在本目录：它是应用级能力，状态与凭证由 session/privacy-session
  单例持有（模块挂载只做状态映射与提示，卸载不关闭保护）。
-->
<template>
  <div class="photo-album">
    <!-- 瞬时提示（错误/导出完成/复制/状态）统一由全局 ToastLayer 渲染（App 根节点单点挂载，--z-toast 最高层） -->

    <!-- 顶部栏：星野导航带（半透明无框；星野底板与溶解边界由 StarlitSky 承担） -->
    <div class="album-top starlit-bar">
      <StarlitSky :seed="11" />
      <div class="top-left">
        <span class="album-title">拾光</span>
        <span class="album-count">{{ photos.length }} 张</span>
        <span class="enc-badge" v-tip="'主密钥已就绪'">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          加密
        </span>
      </div>
      <div class="top-right">
        <button
          class="btn btn-sm privacy-btn"
          :class="{ on: privacyMode, 'is-busy': privacyBusy, 'cursor-not-allowed': privacyButtonDisabled }"
          :disabled="privacyButtonDisabled"
          @click="onPrivacyToggle"
          v-tip="privacyTip"
        >
          <!-- 状态图标随开关切换：开启=保护生效（睁眼），关闭=保护关闭（划斜线眼）；
               两枚图标绝对定位交叉淡入，切换不产生布局抖动 -->
          <span class="privacy-ico">
            <transition name="privacy-ico">
              <svg v-if="privacyMode" key="guarded" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
              <svg v-else key="unguarded" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>
            </transition>
          </span>
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

    <!-- 重打包进度（后台任务运行中）：提供取消入口 -->
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
           失败由通用错误提示（toast）承接，不打断浏览（无提示横幅/进度卡）。 -->
      <CosmicLoading :show="photosLoading && photos.length === 0" text="正在加载照片列表…" />

      <!-- 虚拟滚动容器（相册列表强制采用虚拟滚动）：
           行窗口模型：滚动位置的唯一量化状态是行窗口，像素级移动不产生重建；
           渲染数组引用稳定（未变化的项复用对象），上万照片也只渲染数十 DOM 节点。
           容器高度 = 总行数 × 行高，撑开滚动条；每个 masonry-item 用 translate3d 精确定位。
           no-anim 挂容器（动画关停是全局状态，不属于任何单项——避免 per-item class 抖动） -->
      <div v-if="photos.length > 0" class="masonry-cols" :class="{ 'no-anim': animationDone }" :style="{ height: totalHeight + 'px' }">
        <div
          v-for="ph in visiblePhotos"
          :key="ph.id"
          class="masonry-item"
          :class="{ selected: selectMode && selectedPhotoIds.has(ph.id) }"
          :style="ph._style"
          @mousemove="onCardMove($event)"
          @mouseleave="onCardLeave($event)"
          @click="onPhotoClick(ph)"
        >
          <!-- 文字清晰度铁律：文字层（overlay）与图像层平级分离——
               图像层只保留静态滤镜（照片 3D 倾斜已移除），
               文字祖先链上无 filter / 3D 变换 / 缩放，恒走静态栅格化清晰路径。 -->
          <div class="photo-card glass">
            <div class="photo-thumb" :style="{ backgroundImage: ph.thumb }"></div>
            <div class="photo-overlay">
              <span class="photo-name">{{ ph.name }}</span>
              <span class="photo-size">{{ ph.size }}</span>
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

    <!-- 防截屏保护恢复对话框（隔离态：修复是对账的唯一入口） -->
    <CosmicOverlay :show="showPrivacyRecovery" width="420px" @close="showPrivacyRecovery = false">
      <div class="kv-title">防截屏保护需要修复</div>
      <div class="kv-desc">
        上一次保护状态变更未能完整还原，窗口保护状态未知。点击"立即修复"将按失败前的
        设置对全部窗口重新应用保护；在此之前请勿进行截图或录屏操作。
      </div>
      <div class="kv-actions">
        <button class="btn kv-cancel" @click="showPrivacyRecovery = false">稍后处理</button>
        <button class="btn btn-primary kv-confirm" @click="doPrivacyReconcile">立即修复</button>
      </div>
    </CosmicOverlay>
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
import { onMounted, onUnmounted, computed, ref, watch, defineAsyncComponent } from "vue";
import { isModuleReady } from "../../lib/keyManager";
import { tryGc } from "../../utils/gc";
import StarlitSky from "../common/cosmic/StarlitSky.vue";
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
import { useToastCenter } from "../../composables/useToastCenter";
import { usePhotoData } from "../../composables/photo-album/usePhotoData";
import { usePhotoImport } from "../../composables/photo-album/usePhotoImport";
import { usePhotoExport } from "../../composables/photo-album/usePhotoExport";
import { usePhotoViewer } from "../../composables/photo-album/usePhotoViewer";
import { usePhotoParse } from "../../composables/photo-album/usePhotoParse";
import { usePhotoRepack } from "../../composables/photo-album/usePhotoRepack";
import { usePhotoDelete } from "../../composables/photo-album/usePhotoDelete";
import { useCardShine } from "../../composables/useCardShine";
import { useModuleDialogGuard } from "../../composables/useModuleDialogGuard";
import { resolveChunkSet } from "../../composables/photo-album/chunk-refs";
// 防截屏保护：应用级会话单例（能力归属应用而非组件，模块卸载不关闭保护）
import {
  ensureAdopted as ensurePrivacyAdopted,
  privacyBusy,
  privacyEnabled,
  privacyQuarantined,
  privacyTokenLost,
  reconcilePrivacySession,
  togglePrivacy,
} from "../../session/privacy-session";

/* ---------- 1. Toast 反馈中心（全局单例，最先装配，后续 composable 依赖其 showError 等） ----------
 * 渲染统一归 ToastLayer（最高层）；本模块仅取用通道方法并注入各子 composable */
const { showError, showStatus, showExportDone, showCopied } = useToastCenter();
/** 状态提示（拾光既有 2s 口径；子 composable 的 DI 参数名沿用 showToast） */
const showToast = (msg: string) => showStatus(msg, 2000);

/* ---------- 2. 核心数据层（提供 photos / photoKey / isTauri / 虚拟滚动 / 按需解密） ---------- */
const {
  photos, photoKey, isTauri, photosLoading, animationDone,
  loadError, failedCount,
  scrollRef, totalHeight, visiblePhotos,
  onScroll,
  initVirtualScroll, destroyVirtualScroll,
  decryptPhotoMeta, loadPhotos, releaseThumbUrls, ensurePhotoKey,
  cancelPendingDecrypt,
} = usePhotoData();

/* ===== 加载状态的展示派生（表现层，无业务判断） ===== */
/** 相册内重操作统一忙碌信号：任一在途即禁用全部并发入口。
 *  互斥第一道防线必须在 UI（前端先拦），后端拒绝（导入管线重入守卫）仅作兜底；
 *  解析导入期间若不拦，用户会付出"选文件/加密"成本后才被拒绝。 */
const albumBusy = computed(() =>
  importing.value || parsing.value || importingParsed.value || exporting.value || repackRunning.value,
);
/** 加载失败/降级：以通用错误提示（toast）呈现（不设常驻提示栏） */
watch(loadError, (v) => {
  if (v) showError(v);
});
/** 解密失败计数：首次出现时经 toast 如实告知（便于用户察觉部分照片未就绪） */
watch(failedCount, (n, prev) => {
  if (n > 0 && prev === 0) {
    showError(`已加载 ${photos.value.length - n} 张，${n} 张解密失败`);
  }
});

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

/* ---------- 8. 防截屏保护层（应用级会话单例，界面只做状态映射与提示） ---------- */
/** 模板沿用既有命名：保护是否启用 */
const privacyMode = privacyEnabled;
/** 恢复对话框开关（隔离态下由按钮或错误码打开） */
const showPrivacyRecovery = ref(false);

/** 按钮禁用：处理中或凭证丢失（凭证丢失时无法关闭，须重启接管） */
const privacyButtonDisabled = computed(
  () => !isTauri || privacyBusy.value || privacyTokenLost.value,
);
/** 按钮提示：如实反映当前能力状态，隔离态引导进入修复 */
const privacyTip = computed(() => {
  if (!isTauri) return "防截屏保护仅在桌面端生效";
  if (privacyBusy.value) return "保护状态变更中…";
  if (privacyQuarantined.value) return "保护状态异常，点击修复";
  if (privacyTokenLost.value) return "会话凭证丢失，重启应用可重新接管";
  return privacyMode.value ? "防截屏保护已开启，点击关闭" : "防截屏保护已关闭，点击开启";
});

/**
 * 切换保护：按钮语义随状态（隔离态点击进入修复）
 * 错误码到提示的映射集中在此处，会话层不含任何界面文案。
 */
const onPrivacyToggle = async () => {
  if (privacyQuarantined.value) {
    showPrivacyRecovery.value = true;
    return;
  }
  const outcome = await togglePrivacy();
  if (outcome.ok) {
    showToast(privacyMode.value ? "防截屏保护已开启" : "防截屏保护已关闭");
    return;
  }
  switch (outcome.code) {
    case "PRIVACY_QUARANTINED":
      showPrivacyRecovery.value = true;
      break;
    case "PRIVACY_ROLLED_BACK":
      showError("保护失败，已还原到变更前状态");
      break;
    case "PRIVACY_TRANSITION_SUPERSEDED":
      showError("操作已被新的状态变更取代");
      break;
    case "PRIVACY_TOKEN_MISSING":
    case "PRIVACY_TOKEN_INVALID":
      showError("会话凭证丢失，重启应用可重新接管");
      break;
    case "PRIVACY_LEASE_HELD":
      showError("已有待确认的关闭操作，请稍后重试");
      break;
    case "PRIVACY_IPC_FAILED":
      showError("保护服务暂不可用，请稍后重试");
      break;
    case "RATE_LIMITED":
      showError("操作过于频繁，请稍后再试");
      break;
    case "PRIVACY_BUSY":
      // 连击由单飞与状态机兜住，静默
      break;
    default:
      showError("防截屏保护操作失败，请重试");
  }
};

/** 恢复对话框：立即修复（隔离对账） */
const doPrivacyReconcile = async () => {
  const outcome = await reconcilePrivacySession();
  if (outcome.ok) {
    showPrivacyRecovery.value = false;
    showToast(privacyMode.value ? "防截屏保护已修复" : "残留保护已清除");
    return;
  }
  showError("修复失败，请重试或重启应用");
};

/* ---------- 9. 交互层（卡片指针光晕，共享实现：存签/枢钥/钥域/拾光同一 composable） ---------- */
const { onCardMove, onCardLeave, cancel: cancelShine } = useCardShine();

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

  // 保护会话接管（应用级单例，单飞幂等）：判定待采纳后取得关闭保护所需凭证；
  // 失败不阻断模块加载——状态不可知时按钮按不可用处理
  ensurePrivacyAdopted().catch((e) => {
    console.warn("[privacy] 会话接管失败", e);
  });

  // 虚拟滚动布局初始化收敛至数据层（initVirtualScroll 内部完成 updateLayout + ResizeObserver 注册）
  initVirtualScroll();

  // 首批照片入场动画播完后禁用，避免虚拟滚动时新进入可视区项重播动画导致闪烁
  setTimeout(() => { animationDone.value = true; }, 1500);

  // 安全前置校验闸门：模块密钥已由 MainView 登录时缓存到 keyManager 会话，直接读取。
  // 未就绪时不加载、不提示（进入拾光本应经过安全管理验证），仅留控制台告警便于排查
  if (isTauri) {
    if (isModuleReady("photo") && ensurePhotoKey()) {
      loadPhotos();
    } else {
      console.warn("[photo] 模块密钥不可用，跳过加载（应由安全管理验证后进入拾光）");
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
 *   - 释放浏览器模式照片 Blob URL
 *   - 清空照片数组释放引用 + 主动触发 V8 Major GC
 *   - 清零模块子密钥（全局密钥由 keyManager 统一管理）
 *
 * 不在卸载时改动防截屏保护：保护是应用级能力，不由模块生命周期驱动。
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
  cancelShine();

  // 取消去抖中未触发的可视区解密批次（防止卸载后写状态）
  cancelPendingDecrypt();

  // 销毁虚拟滚动（释放 ResizeObserver）
  destroyVirtualScroll();

  // 释放查看器 Blob URL
  cleanupViewer();

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

/* 顶部栏：星野导航带仅承载布局（无边框/圆角/投影 —— 底板与左右溶解边界由 StarlitSky 承担） */
.album-top { display: flex; align-items: center; justify-content: space-between; padding: 10px 16px; flex-shrink: 0; animation: slide-down 0.5s var(--ease) both; }
@keyframes slide-down { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
.top-left { display: flex; align-items: center; gap: 8px; }
.album-title { font-size: 13px; color: var(--text-primary); letter-spacing: 1px; }
.album-count { font-size: 10px; color: var(--text-muted); font-family: var(--font); }
.enc-badge { display: flex; align-items: center; gap: 3px; font-size: 9px; color: var(--accent); font-family: var(--font); letter-spacing: 0.5px; padding: 2px 6px; border: 1px solid rgba(0,212,255,0.2); border-radius: 8px; background: rgba(0,212,255,0.05); }
.enc-badge svg { width: 10px; height: 10px; }
.top-right { display: flex; gap: 8px; align-items: center; }
.privacy-btn { position: relative; display: flex; align-items: center; justify-content: center; width: 32px; height: 32px; padding: 0; }
/* 双状态图标叠放容器：两枚图标绝对定位交叉淡入，切换不产生布局抖动 */
.privacy-ico { position: relative; display: block; width: 15px; height: 15px; }
.privacy-ico svg { position: absolute; inset: 0; width: 15px; height: 15px; }
.privacy-ico-enter-active, .privacy-ico-leave-active { transition: opacity 0.18s var(--ease); }
.privacy-ico-enter-from, .privacy-ico-leave-to { opacity: 0; }
.privacy-btn.on { color: var(--accent); border-color: rgba(0,212,255,0.3); background: rgba(0,212,255,0.08); }
/* 禁用态光标：可点击与不可点击必须可区分 */
.privacy-btn:disabled { cursor: not-allowed; }
/* 持久不可用（凭证丢失/非桌面端）：视觉降级；处理中在途窗口极短，
   不做降级以免快速开关时按钮闪烁（光标与悬浮提示已表达处理中） */
.privacy-btn:disabled:not(.is-busy),
.privacy-btn:disabled:not(.is-busy):hover {
  opacity: 0.35;
  border-color: var(--border-glass);
  background: rgba(var(--bg-tertiary-rgb), 0.62);
  color: var(--text-muted);
}

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

/* 后台进度横幅（重打包）：进度文案 + 取消迁移入口 */
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
/* 虚拟滚动：绝对定位网格容器（行窗口模型，由 JS 精确计算每项 translate3d 定位）；
      列数/行高由 JS computeColumns + itemWidth 计算，响应式断点与原媒体查询一致 */
.masonry-cols { position: relative; width: 100%; }
/* 条目隔离为独立堆叠上下文：内部光影层（z 0）与卡片（z 1）的层级不外泄，
   跨条目遮挡由文档树序保证（后绘制者在上） */
.masonry-item { position: absolute; top: 0; left: 0; cursor: pointer; isolation: isolate; }

/* hover 悬浮光影层（滚动性能第 2 铁律的阴影落点）——
   原实现让 box-shadow 参与 0.3s 过渡：大半径模糊阴影是重绘型属性，过渡期
   逐帧重绘卡片；滚动中卡片掠过指针时连续触发，是滚动掉帧主因之一。
   现改为"固定阴影纹理 + opacity/transform 过渡"（两者均走合成器）：
   层仅在 hover 时可见（visibility 门控，非 hover 态不参与栅格化），
   translateY 与卡片抬升同步（视觉上与旧版悬浮阴影加深一致）。 */
.masonry-item::before {
  content: ''; position: absolute; inset: 0; z-index: 0; border-radius: var(--radius);
  pointer-events: none; visibility: hidden; opacity: 0;
  box-shadow: 0 16px 40px rgba(0,0,0,0.5), 0 0 20px rgba(0,212,255,0.12);
  transition: opacity 0.3s var(--ease), transform 0.3s var(--ease), visibility 0s linear 0.3s;
}
/* 进入时 visibility 立即生效；离开时延迟到淡出结束再隐藏（保持淡出过程可见） */
.masonry-item:hover::before {
  visibility: visible; opacity: 1; transform: translateY(-6px);
  transition: opacity 0.3s var(--ease), transform 0.3s var(--ease), visibility 0s;
}

/* 入场动画作用于 .photo-card 子元素，避免与 masonry-item 的 translate3d 定位 transform 冲突
   首批加载播放（animationDone=false）；1.5s 后由容器 no-anim 关停，防止虚拟滚动新进入项重播闪烁。
   no-anim 挂在容器而非逐项：动画关停是全局状态，挂容器后切换 1.5s 只 patch 一个节点。
   填充模式必须为 backwards，不得改回 both/forwards：动画声明优先级高于普通/内联声明，
   前向填充会在动画结束后继续用动画终态压住卡片悬浮抬升（transform 被覆盖），
   表现为「进入模块后一段时间内悬停无抬升」；终态关键帧与基础样式一致，无需前向填充 */
.masonry-cols:not(.no-anim) .photo-card { animation: photo-reveal 0.65s cubic-bezier(0.22, 1, 0.36, 1) backwards; }
.masonry-cols.no-anim .photo-card { animation: none; }

/* 高级照片入场动画：从缩放+下移 → 还原，配合逐个动态加载产生行优先瀑布入场效果 */
@keyframes photo-reveal {
  0%   { opacity: 0; transform: scale(0.85) translateY(20px); }
  50%  { opacity: 1; transform: scale(0.97) translateY(4px); }
  100% { opacity: 1; transform: scale(1) translateY(0); }
}

/* 照片卡片 · 滚动性能第 2 铁律（禁止重绘型属性参与过渡）+ 文字清晰度铁律：
   - 卡片过渡只保留 transform（合成器路径）——整数像素平移（-6px 悬浮抬升，
     合成器做整数设备像素吸附），文字层（.photo-overlay）位于卡片层，保持清晰；
   - border-color / box-shadow 全状态恒定（下方钉死 .glass 的 hover 漂移），
     阴影加深改由 .masonry-item::before 光影层承担；hover 提亮改由 ::before
     提亮层承担（白色叠加，仅 opacity 过渡）；被替换的 box-shadow / filter
     过渡——两者都是重绘型属性，过渡期逐帧重绘，是滚动掉帧的主因；
   - 图像层 .photo-thumb 只保留静态降饱和滤镜，不做任何 transform
     （照片 3D 倾斜已按用户决策整体移除）；
   - contain: layout style 隔离内外布局/样式计算（不做 paint 裁剪：避开
     自身盒阴影绘制与裁剪实现的灰区）；isolation 使提亮层（z 2）< 文字遮罩
     （z 3）< 光晕（z 4）的层序封闭在卡内，不向相邻条目外泄；
   - 禁令：不得恢复 will-change: transform / transform-style: preserve-3d；
     不得把文字/浮层节点移回 .photo-thumb（filter 子树会禁用文字亚像素抗锯齿）。 */
.photo-card {
  position: relative; overflow: hidden; border-radius: var(--radius);
  z-index: 1;
  contain: layout style; isolation: isolate;
  transition: transform 0.3s var(--ease);
}
/* 钉死 .glass:hover 的边框/阴影漂移：卡片外观任何状态恒定，hover 不再触发
   边框与阴影的瞬时重绘（取值与 styles/components.css 的 .glass 基线一致，
   基线改动须同步此处） */
.photo-card.glass,
.photo-card.glass:hover {
  border-color: var(--border-glass);
  box-shadow: 0 8px 32px rgba(var(--black-rgb), 0.4), 0 0 1px rgba(var(--white-rgb), 0.05), inset 0 1px 0 rgba(var(--white-rgb), 0.04);
}
.photo-card:hover { transform: translateY(-6px); }
/* 提亮层（替代 hover 的 filter 提亮）：白色叠加层仅 opacity 过渡（合成器）。
   强度 0.08 ≈ 原 brightness(0.9→1) 的观感差；饱和度不随 hover 提升
   （合成器约束下无法等价实现 saturate 增益，观感差异记录于修复文档） */
.photo-card::before {
  content: ''; position: absolute; inset: 0; z-index: 2; border-radius: inherit;
  pointer-events: none; background: rgba(255,255,255,0.08); opacity: 0;
  transition: opacity 0.3s var(--ease);
}
.photo-card:hover::before { opacity: 1; }
/* 图像层：静态降饱和滤镜保留（未悬浮观的基色不变）；无 transform、无过渡 */
.photo-thumb { background-size: cover; background-position: center; position: relative; z-index: 1; filter: saturate(0.85) brightness(0.9); aspect-ratio: 1 / 1; }
.photo-overlay { position: absolute; bottom: 0; left: 0; right: 0; z-index: 3; padding: 10px 12px; background: linear-gradient(180deg, transparent, rgba(0,0,0,0.85)); opacity: 0; transition: opacity 0.3s; display: flex; justify-content: space-between; align-items: flex-end; }
.photo-card:hover .photo-overlay { opacity: 1; }
.photo-name { font-size: 11px; color: var(--text-primary); font-family: var(--font); }
.photo-size { font-size: 9px; color: var(--accent); font-family: var(--font); letter-spacing: 0.5px; }

/* 滚动静默态（滚动性能第 3 铁律）：滚动期间冻结本网格的一切 hover 过渡与
   入场动画（data-scrolling 由 usePhotoData 静默态挂载在滚动容器上）——
   卡片掠过指针不再产生任何闪烁与重绘，网格保持静止态；停止滚动
   ~120ms 后移除标记，hover 视觉经过渡恢复（追帧补齐）。
   冻结方式：把 hover 结果压回非 hover 值 + 关停过渡/动画（而非隐藏元素），
   解冻瞬间从当前计算值过渡到 hover 值，观感自然。 */
.masonry-scroll[data-scrolling] .photo-card,
.masonry-scroll[data-scrolling] .photo-card::before,
.masonry-scroll[data-scrolling] .photo-overlay,
.masonry-scroll[data-scrolling] .photo-shine,
.masonry-scroll[data-scrolling] .masonry-item::before {
  transition: none !important;
}
/* 入场动画用"暂停"而非"移除"冻结：若用 animation: none，解冻瞬间动画会
   重新从 0% 播放（进入模块 1.5s 窗口内滚动 → 停稳后整屏卡片重新淡入闪烁）；
   paused 相位连续，停稳后从暂停点继续（与 idle-governance 同款实现）。 */
.masonry-scroll[data-scrolling] .photo-card {
  animation-play-state: paused !important;
}
.masonry-scroll[data-scrolling] .photo-card:hover { transform: none; }
.masonry-scroll[data-scrolling] .photo-card:hover::before { opacity: 0; }
.masonry-scroll[data-scrolling] .photo-card:hover .photo-overlay { opacity: 0; }
.masonry-scroll[data-scrolling] .photo-card:hover .photo-shine { opacity: 0; }
.masonry-scroll[data-scrolling] .masonry-item:hover::before { visibility: hidden; opacity: 0; transform: none; }

/* 选择删除模式：仅红框选中。环形描边内嵌于缩略图内部渲染，不超出元素边界，
   滚动容器边缘处（首行顶部/首列两侧）的描边不会被 overflow 裁剪；
   选择态重置为全圆角，使描边跟随卡片四角圆弧（默认非对称圆角会造成
   方角描边被圆形裁剪切掉，形成边框缺口） */
.masonry-item.selected .photo-thumb {
  border-radius: var(--radius);
  box-shadow: inset 0 0 0 2px var(--danger);
}

/* 照片指针光晕（图像层之上的独立表面，常规混合）；位置与强度口径与卡片
   .card-shine 一致：位置由共享 useCardShine 写入 --shine-x / --shine-y，
   强度取 tokens.css --shine-alpha / --shine-reach（Wave 54 收口）；
   z 4 使其位于提亮层（z 2）与文字遮罩（z 3）之上（沿用原树序层叠） */
.photo-shine { position: absolute; inset: 0; z-index: 4; border-radius: var(--radius); pointer-events: none; opacity: 0; transition: opacity 0.3s; background: radial-gradient(circle at var(--shine-x, 50%) var(--shine-y, 50%), rgba(var(--accent-rgb), var(--shine-alpha)), transparent var(--shine-reach)); }
.photo-card:hover .photo-shine { opacity: 1; }

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
