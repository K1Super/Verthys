/*
 * china_region.spec.ts — 全国区划树完整性 + 路径回解契约
 *
 * 覆盖：省 / 市 / 区三级名称路径的无损回解、历史自由文本的不可回解判定、
 *   空值与部分路径的可回解语义，以及数据源自身的结构完整性（层级非空、
 *   同级名称唯一）。最后一项是回解可靠性的前提：同级重名会让路径无法唯一
 *   还原，必须在此处挡住而非留给运行时。
 */
import { describe, it, expect } from "vitest";
import { CHINA_REGIONS } from "../constants/china_regions";
import {
  CHINA_REGION_PATH_SEPARATOR,
  emptyChinaRegionPath,
  joinChinaRegionPath,
  parseChinaRegionPath,
} from "./china_region";

describe("区划树完整性", () => {
  it("覆盖 34 个省级行政区（含港澳台），每个地级至少一个区县", () => {
    expect(CHINA_REGIONS).toHaveLength(34);
    for (const province of CHINA_REGIONS) {
      expect(province.cities.length).toBeGreaterThan(0);
      for (const city of province.cities) {
        expect(city.districts.length).toBeGreaterThan(0);
      }
    }
  });

  it("同级名称唯一：省级全局唯一、地级省内唯一、区县市内唯一", () => {
    const provinceNames = CHINA_REGIONS.map((province) => province.name);
    expect(new Set(provinceNames).size).toBe(provinceNames.length);

    for (const province of CHINA_REGIONS) {
      const cityNames = province.cities.map((city) => city.name);
      expect(new Set(cityNames).size).toBe(cityNames.length);
      for (const city of province.cities) {
        expect(new Set(city.districts).size).toBe(city.districts.length);
      }
    }
  });

  it("名称不含路径分隔符或空白：拼接与回解不会产生歧义", () => {
    for (const province of CHINA_REGIONS) {
      expect(province.name).not.toMatch(/[/\s]/);
      for (const city of province.cities) {
        expect(city.name).not.toMatch(/[/\s]/);
        for (const district of city.districts) {
          expect(district).not.toMatch(/[/\s]/);
        }
      }
    }
  });

  it("包含港澳台与常用区划样本", () => {
    const names = CHINA_REGIONS.map((province) => province.name);
    expect(names).toEqual(expect.arrayContaining(["香港特别行政区", "澳门特别行政区", "台湾省"]));

    const guangdong = CHINA_REGIONS.find((province) => province.name === "广东省")!;
    const shenzhen = guangdong.cities.find((city) => city.name === "深圳市")!;
    expect(shenzhen.districts).toContain("南山区");
  });

  it("每个区县都能按完整路径无损回解（回解与数据同源）", () => {
    for (const province of CHINA_REGIONS) {
      for (const city of province.cities) {
        for (const district of city.districts) {
          const path = joinChinaRegionPath({ province: province.name, city: city.name, district });
          expect(parseChinaRegionPath(path, CHINA_REGIONS)).toEqual({
            province: province.name,
            city: city.name,
            district,
            matched: true,
          });
        }
      }
    }
  });
});

describe("路径回解", () => {
  it("完整三级路径命中对应父级", () => {
    expect(parseChinaRegionPath("广东省/深圳市/南山区", CHINA_REGIONS)).toEqual({
      province: "广东省",
      city: "深圳市",
      district: "南山区",
      matched: true,
    });
  });

  it("省级与省+地级部分路径按可回解处理", () => {
    expect(parseChinaRegionPath("广东省", CHINA_REGIONS)).toEqual({
      province: "广东省",
      city: "",
      district: "",
      matched: true,
    });
    expect(parseChinaRegionPath("广东省/深圳市", CHINA_REGIONS)).toEqual({
      province: "广东省",
      city: "深圳市",
      district: "",
      matched: true,
    });
  });

  it("空值按空路径处理，不误报历史值冲突", () => {
    expect(parseChinaRegionPath("", CHINA_REGIONS)).toEqual(emptyChinaRegionPath());
    expect(parseChinaRegionPath("   ", CHINA_REGIONS)).toEqual(emptyChinaRegionPath());
    expect(parseChinaRegionPath("", CHINA_REGIONS).matched).toBe(true);
  });

  it("历史自由文本不可回解：三个下拉框一律留空", () => {
    expect(parseChinaRegionPath("北京市朝阳区望京街道", CHINA_REGIONS)).toEqual({
      province: "",
      city: "",
      district: "",
      matched: false,
    });
    expect(parseChinaRegionPath("某省/某市/某区", CHINA_REGIONS)).toEqual({
      province: "",
      city: "",
      district: "",
      matched: false,
    });
  });

  it("区县不属于所选地级时不跨级匹配（同名区县不得选错父级）", () => {
    // 「大安区」同时存在于台北市与台中市；挂在南京市下必须判为不可回解
    const path = joinChinaRegionPath({ province: "江苏省", city: "南京市", district: "大安区" });
    expect(parseChinaRegionPath(path, CHINA_REGIONS).matched).toBe(false);
  });

  it("分隔符不符、空段或超过三级均判为不可回解", () => {
    expect(parseChinaRegionPath("广东省 深圳市 南山区", CHINA_REGIONS).matched).toBe(false);
    expect(parseChinaRegionPath("广东省//南山区", CHINA_REGIONS).matched).toBe(false);
    expect(parseChinaRegionPath("广东省/深圳市/南山区/粤海街道", CHINA_REGIONS).matched).toBe(false);
  });

  it("路径两端空白被忽略", () => {
    expect(parseChinaRegionPath(" 广东省 / 深圳市 / 南山区 ", CHINA_REGIONS)).toEqual({
      province: "广东省",
      city: "深圳市",
      district: "南山区",
      matched: true,
    });
  });
});

describe("路径拼接", () => {
  it("空段自动丢弃，顺序恒为省/市/区", () => {
    expect(joinChinaRegionPath({ province: "广东省", city: "", district: "" })).toBe("广东省");
    expect(joinChinaRegionPath({ province: "广东省", city: "深圳市", district: "" })).toBe(
      `广东省${CHINA_REGION_PATH_SEPARATOR}深圳市`,
    );
    expect(joinChinaRegionPath({})).toBe("");
  });

  it("三段齐备时与回解互逆", () => {
    const path = joinChinaRegionPath({ province: "台湾省", city: "台北市", district: "大安区" });
    expect(path).toBe("台湾省/台北市/大安区");
    expect(parseChinaRegionPath(path, CHINA_REGIONS)).toEqual({
      province: "台湾省",
      city: "台北市",
      district: "大安区",
      matched: true,
    });
  });
});
