<!--
  VaultRegionPicker.vue — 全国省 / 市 / 区三级联动控件（存签「地区」字段唯一渲染源）

  形态：三枚并置选择器（省 → 市 → 区），触发面与选项弹层统一由 VaultSelect 承担；
        历史自由文本无法回解时降级为一行提示，三个选择器留空。

  为什么按需加载区划数据：全国三级区划是约 70KB 的静态数据，只有地址类
  条目真正打开登记窗口时才需要。动态 import 让它留在独立分块中，既不进入
  首屏主包，也不发起任何网络请求 —— 保险库内容与检索不出本机。

  落盘语义：控件只产出「省/市/区」名称路径（见 lib/china_region）。未命中
  的历史值不覆写、不截断：只有用户在联动框中显式选择时才产生新路径。

  用法:
    <VaultRegionPicker v-model="values.region" />
-->
<template>
  <div class="region-picker">
    <div class="region-selects">
      <VaultSelect
        class="region-select"
        compact
        :model-value="selectedProvince"
        :options="provinceNames"
        :placeholder="loading ? '载入地区…' : '省份'"
        :disabled="loading || loadFailed"
        aria-label="省份"
        @update:model-value="onProvinceChange"
      />

      <VaultSelect
        class="region-select"
        compact
        :model-value="selectedCity"
        :options="cityNames"
        :placeholder="selectedProvince ? '城市' : '—'"
        :disabled="loading || loadFailed || !selectedProvince"
        aria-label="城市"
        @update:model-value="onCityChange"
      />

      <VaultSelect
        class="region-select"
        compact
        :model-value="selectedDistrict"
        :options="districtNames"
        :placeholder="selectedCity ? '区县' : '—'"
        :disabled="loading || loadFailed || !selectedCity"
        aria-label="区县"
        @update:model-value="onDistrictChange"
      />
    </div>

    <!-- 不可回解的历史值：原样提示，不伪造选中项（保存时原值保持不变） -->
    <p v-if="legacyText" class="kv-hint region-hint is-legacy">已存：{{ legacyText }} · 重新选择后生效</p>
    <p v-else-if="loadFailed" class="kv-hint region-hint">
      地区数据加载失败
      <button type="button" class="region-retry" @click="loadRegions">重试</button>
    </p>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, shallowRef, watch } from "vue";
import type { ChinaRegionProvince } from "../../../constants/china_regions";
import { joinChinaRegionPath, parseChinaRegionPath } from "../../../lib/util/china_region";
import VaultSelect from "../../common/verthys-ui/VaultSelect.vue";

const props = defineProps<{
  /** 落盘的「省/市/区」名称路径；历史自由文本原样传入 */
  modelValue: string;
}>();

const emit = defineEmits<{
  (e: "update:modelValue", value: string): void;
}>();

/** 区划树（shallowRef：数据只读，无需深度代理三千余条节点） */
const provinces = shallowRef<readonly ChinaRegionProvince[]>([]);
const loading = ref(true);
const loadFailed = ref(false);

/** 当前三级选中项（由落盘路径回解，或由用户逐级选择） */
const selectedProvince = ref("");
const selectedCity = ref("");
const selectedDistrict = ref("");

/** 无法回解的历史值（非空时原样提示，且不据此改写表单取值） */
const legacyText = ref("");

/** 当前省份下的地级清单 */
const cityOptions = computed(
  () => provinces.value.find((province) => province.name === selectedProvince.value)?.cities ?? [],
);

/** 当前地级下的区县清单 */
const districtOptions = computed(
  () => cityOptions.value.find((city) => city.name === selectedCity.value)?.districts ?? [],
);

/** 选择器候选项：只投影名称，值即落盘路径中的同名段 */
const provinceNames = computed(() => provinces.value.map((province) => province.name));
const cityNames = computed(() => cityOptions.value.map((city) => city.name));
const districtNames = computed(() => districtOptions.value);

/** 以落盘取值重建三个下拉框的选中态 */
const syncFromValue = (): void => {
  if (provinces.value.length === 0) return;
  const parsed = parseChinaRegionPath(props.modelValue, provinces.value);
  selectedProvince.value = parsed.province;
  selectedCity.value = parsed.city;
  selectedDistrict.value = parsed.district;
  legacyText.value = parsed.matched ? "" : props.modelValue.trim();
};

/* 加载序号：窗口快速开关时，较早发起的加载不得覆盖最新一次的状态 */
let loadSeq = 0;
const loadRegions = async (): Promise<void> => {
  const seq = ++loadSeq;
  loading.value = true;
  loadFailed.value = false;
  try {
    const module = await import("../../../constants/china_regions");
    if (seq !== loadSeq) return;
    provinces.value = module.CHINA_REGIONS;
    syncFromValue();
  } catch {
    if (seq !== loadSeq) return;
    loadFailed.value = true;
  } finally {
    if (seq === loadSeq) loading.value = false;
  }
};

onMounted(loadRegions);

/* 卸载即作废未完成的加载：登记窗口快速开关时，迟到完成的 import 不得
   再向已销毁的实例写入状态。 */
onBeforeUnmount(() => {
  loadSeq += 1;
});

/* 打开窗口 / 编辑其它条目时父级会整体替换取值：同步重建选中态。
   只在取值变化时触发，不监听本地选中项，避免与用户选择形成回环。 */
watch(() => props.modelValue, syncFromValue);

/** 把当前选择投影为落盘路径（空段自动丢弃） */
const emitPath = (province: string, city: string, district: string): void => {
  legacyText.value = "";
  emit("update:modelValue", joinChinaRegionPath({ province, city, district }));
};

/* 逐级联动：换省清空市与区，换市清空区 —— 避免留下不属于新父级的旧值。
   选择器直接给出选中值，不再从原生 change 事件里取。 */
const onProvinceChange = (province: string): void => {
  selectedProvince.value = province;
  selectedCity.value = "";
  selectedDistrict.value = "";
  emitPath(province, "", "");
};

const onCityChange = (city: string): void => {
  selectedCity.value = city;
  selectedDistrict.value = "";
  emitPath(selectedProvince.value, city, "");
};

const onDistrictChange = (district: string): void => {
  selectedDistrict.value = district;
  emitPath(selectedProvince.value, selectedCity.value, district);
};
</script>

<style scoped>
.region-selects {
  display: grid;
  grid-template-columns: 1.15fr 1fr 1fr;
  gap: 6px;
  min-width: 0;
}

/* 三列并置：列宽在这里定义，触发面与弹层由 VaultSelect 统一承担 */
.region-select {
  min-width: 0;
}

/* 历史值与区划更名同属「需要用户确认」的状态：只用警示色文字，不加底色框 */
.region-hint.is-legacy { color: var(--warning); }

.region-retry {
  margin-left: 4px; padding: 2px 8px;
  background: none;
  border: 1px solid var(--border-glass); border-radius: 5px;
  color: var(--accent);
  font-size: 10.5px; font-family: var(--font);
  cursor: pointer;
  transition: color var(--dur-fast) var(--ease), border-color var(--dur-fast) var(--ease);
}
.region-retry:hover { color: var(--text-primary); border-color: var(--border-hover); }
.region-retry:focus-visible { outline: 1px solid var(--border-hover); outline-offset: 1px; }
</style>
