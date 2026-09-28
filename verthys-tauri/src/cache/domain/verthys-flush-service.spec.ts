/**
 * verthys-flush-service.spec.ts — 落盘服务行为级测试
 *
 * 覆盖与跨层预算常量绑定的两条关键行为：
 *   - 重试次数以权威值执行（硬编码与生成值并存曾导致静默漂移）
 *   - 落盘自查超时按权威值生效，IPC 悬挂不再无限等待
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { verthysFlush, verthysVerifyDiskPersist } from "../../lib/verthys";
import {
  FLUSH_MAX_RETRIES,
  FLUSH_RETRY_BACKOFF_MS,
  FLUSH_VERIFY_TIMEOUT_MS,
} from "../../constants/photo_budget.generated";
import { VerthysFlushService } from "./verthys-flush-service";

vi.mock("../../lib/verthys", () => ({
  verthysFlush: vi.fn(),
  verthysDeleteRecords: vi.fn(),
  verthysVerifyDiskPersist: vi.fn(),
}));

const flushMock = vi.mocked(verthysFlush);
const verifyMock = vi.mocked(verthysVerifyDiskPersist);

type VerifyResult = Awaited<ReturnType<typeof verthysVerifyDiskPersist>>;

describe("VerthysFlushService 落盘行为", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    flushMock.mockReset();
    verifyMock.mockReset();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("flush 持续失败：重试次数等于跨层预算权威值", async () => {
    flushMock.mockResolvedValue(false);
    const service = new VerthysFlushService(() => "C:/fake.verthys");
    const pending = service.persistVerthysDetailed();
    // 只推进退避窗口（有界推进）：权威重试次数决定退避总时长，
    // 避免触发单次 flush 的超时兜底计时器。
    await vi.advanceTimersByTimeAsync(FLUSH_RETRY_BACKOFF_MS * FLUSH_MAX_RETRIES);
    const outcome = await pending;
    expect(flushMock).toHaveBeenCalledTimes(FLUSH_MAX_RETRIES);
    expect(outcome.kind).toBe("not_persisted");
  });

  it("落盘自查悬挂：超时按权威值生效并进入重试，最终按已落盘告警收束", async () => {
    flushMock.mockResolvedValue(true);
    verifyMock.mockImplementation(() => new Promise<VerifyResult>(() => {}));
    const service = new VerthysFlushService(() => "C:/fake.verthys");
    const pending = service.persistVerthysDetailed();

    // 超时窗口内不得重试（证明等待边界由权威超时值给出）
    await vi.advanceTimersByTimeAsync(FLUSH_VERIFY_TIMEOUT_MS);
    expect(verifyMock).toHaveBeenCalledTimes(1);
    expect(flushMock).toHaveBeenCalledTimes(1);

    // 超时 → 退避 → 下一次尝试
    await vi.advanceTimersByTimeAsync(FLUSH_RETRY_BACKOFF_MS);
    expect(flushMock).toHaveBeenCalledTimes(2);

    // 完成其余两次自查超时与退避
    await vi.advanceTimersByTimeAsync(
      FLUSH_VERIFY_TIMEOUT_MS * 2 + FLUSH_RETRY_BACKOFF_MS * 2,
    );
    const outcome = await pending;
    expect(verifyMock).toHaveBeenCalledTimes(FLUSH_MAX_RETRIES);
    expect(flushMock).toHaveBeenCalledTimes(FLUSH_MAX_RETRIES);
    // flush 已成功（数据已 fsync），自查未过按"已落盘告警"收束，不得判为未落盘
    expect(outcome.kind).toBe("partial_persisted");
  });
});