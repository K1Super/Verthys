use libloading::Symbol;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::log::init_diag;
use crate::runtime::ffi_types::*;
use crate::runtime::protocol::{KernelStatusReport, SecurityStatusReport};

use super::{ffi_call, Worker};

#[cfg(windows)]
extern "system" {
    /// 仅用于父进程注入的匿名事件脉冲；句柄值来自签名 IPC 下发。
    fn SetEvent(h_event: *mut std::ffi::c_void) -> i32;
}

/// UUID 转小写十六进制（32 字符，仅用于锚点列表展示）。
fn uuid_hex(uuid: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for byte in uuid {
        out.push_str(&format!("{:02x}", byte));
    }
    out
}

impl Worker {
    /// 运行时切换安全预设档位（0=BALANCED / 1=SECURE / 2=PERFORMANCE）
    ///
    /// 双缓冲原子发布，切换立即生效；重复切到当前档为幂等 no-op。
    /// 失败回退：DLL 导出缺失（旧版核心）返回 0xFFFFFFFF，由上层可见报告。
    pub(crate) fn call_switch_security_preset(&self, preset: u32) -> u32 {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysSwitchSecurityPresetFn> =
                match lib.get(b"Verthys_SwitchSecurityPreset") {
                    Ok(f) => f,
                    Err(_) => return 0xFFFFFFFF,
                };
            ffi_call(|| { func(self.handle, preset) }).unwrap_or(0xFFFFFFFF)
        }
    }

    /// 查询活跃安全预设档位（快照读取）
    ///
    /// 返回 Ok(档位代号 0/1/2)；失败返回 Err(错误码/0xFFFFFFFF)，
    /// 由上层据此做切档回读校验（不一致即判定切换未生效）。
    pub(crate) fn call_get_security_preset(&self) -> Result<u32, u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetSecurityPresetFn> =
                match lib.get(b"Verthys_GetSecurityPreset") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let mut preset: u32 = 0;
            let rc = ffi_call(|| { func(self.handle, &mut preset as *mut u32) })
                .unwrap_or(0xFFFFFFFF);
            if rc != VERTHYS_OK {
                return Err(rc);
            }
            Ok(preset)
        }
    }

    /// 查询指定档位的特性位投影（跨层特性契约）
    ///
    /// 返回 Ok(特性位)；失败返回 Err(错误码/0xFFFFFFFF)。
    pub(crate) fn call_get_preset_feature_bits(&self, preset: u32) -> Result<u32, u32> {
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetPresetFeatureBitsFn> =
                match lib.get(b"Verthys_GetPresetFeatureBits") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let mut bits: u32 = 0;
            let rc = ffi_call(|| { func(self.handle, preset, &mut bits as *mut u32) })
                .unwrap_or(0xFFFFFFFF);
            if rc != VERTHYS_OK {
                return Err(rc);
            }
            Ok(bits)
        }
    }

    /* ================================================================ *
     * 动态防护 7 路径状态实时查询               *
     *                                                                *
     * FFI 调用 Verthys_GetSecurityStatus（RUNTIME 级实时复检，非 BOOT     *
     * 缓存快照）。防御状态为进程级事实：worker 启动即持有 handle，      *
     * 锁定态/未挂载态均可查询（verthys.h 行为契约）。                  *
     * ================================================================ */

    /// 查询动态防护状态。Err(错误码)：INVALID（参数异常）/ INTERNAL（复检管线异常）
    pub(crate) fn call_security_status(&self) -> Result<SecurityStatusReport, u32> {
        /* C 契约：reserved 必须置零传递（zeroed 全量置零，满足契约） */
        let mut st: VerthysSecurityStatusC = unsafe { std::mem::zeroed() };
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetSecurityStatusFn> =
                match lib.get(b"Verthys_GetSecurityStatus") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let rc = ffi_call(|| { func(self.handle, &mut st as *mut VerthysSecurityStatusC) }).unwrap_or(0xFFFFFFFF);
            if rc != VERTHYS_OK {
                return Err(rc);
            }
        }
        Ok(SecurityStatusReport {
            path_state: st.path_state,
            blocked_count: st.blocked_count,
            degraded_count: st.degraded_count,
            failed_count: st.failed_count,
            all_critical_blocked: st.all_critical_blocked != 0,
            has_degraded: st.has_degraded != 0,
            path_reason: st.path_reason,
            limited_count: st.limited_count,
            policy_flags: st.policy_flags,
            checked_at_unix_ms: st.checked_at_unix_ms,
            kernel_status: self.call_kernel_status(),
        })
    }

    /// 查询内核加固状态。符号缺失（旧核心）返回 None，不使 security_status 失败。
    pub(crate) fn call_kernel_status(&self) -> Option<KernelStatusReport> {
        let mut st: VerthysKernelStatusC = unsafe { std::mem::zeroed() };
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysGetKernelStatusFn> =
                match lib.get(b"Verthys_GetKernelStatus") {
                    Ok(f) => f,
                    Err(_) => return None,
                };
            let rc = ffi_call(|| {
                func(self.handle, &mut st as *mut VerthysKernelStatusC)
            })
            .unwrap_or(0xFFFFFFFF);
            if rc != VERTHYS_OK {
                return None;
            }
        }
        Some(KernelStatusReport {
            state: st.state,
            reason: st.reason,
            capabilities: st.capabilities,
            protocol_major: st.protocol_major,
            protocol_minor: st.protocol_minor,
        })
    }

    /* ================================================================ *
     * 回退锚点维护（API 0x0016）                                       *
     * ================================================================ */

    /// 列出本机回退锚点。返回值：(条目, 状态文件状态)。
    /// 状态：0=absent / 1=ok / 2=corrupt（corrupt 由 C 层返回错误码，
    /// 不会走到 Ok 分支）。
    pub(crate) fn call_anchor_list(
        &self,
    ) -> Result<(Vec<crate::runtime::protocol::AnchorEntry>, u32), u32> {
        const CAP: usize = 64;
        let mut raw: Vec<VerthysAnchorInfoC> = Vec::with_capacity(CAP);
        for _ in 0..CAP {
            raw.push(VerthysAnchorInfoC {
                struct_size: std::mem::size_of::<VerthysAnchorInfoC>() as u32,
                uuid: [0u8; 16],
                generation: 0,
                witness_state: 0,
                reserved: 0,
            });
        }
        let mut count: u32 = 0;
        let mut state: u32 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysRollbackAnchorListFn> =
                match lib.get(b"Verthys_RollbackAnchorList") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let rc = ffi_call(|| {
                func(
                    self.handle,
                    raw.as_mut_ptr(),
                    CAP as u32,
                    &mut count,
                    &mut state,
                )
            })
            .unwrap_or(0xFFFFFFFF);
            if rc != VERTHYS_OK {
                return Err(rc);
            }
        }
        if count as usize > CAP {
            return Err(0x0000000F); // RESOURCE_LIMIT：C 层保证不会发生
        }
        let mut entries = Vec::with_capacity(count as usize);
        for entry in raw.iter().take(count as usize) {
            let witness = match entry.witness_state {
                1 => "active",
                2 => "dead",
                3 => "tampered",
                _ => "unknown",
            };
            entries.push(crate::runtime::protocol::AnchorEntry {
                uuid: uuid_hex(&entry.uuid),
                generation: entry.generation,
                witness: witness.to_string(),
            });
        }
        Ok((entries, state))
    }

    /// 批量释放锚点：一次 FFI 调用完成状态加载、压缩与落盘。
    ///
    /// 返回按输入顺序的 `(released, cleanup_failed)`；任何 C 层错误原样
    /// 返回。输入数量与 C 层上限一致（1..64），空集直接拒绝。
    pub(crate) fn call_anchor_release_batch(
        &self,
        uuids: &[[u8; 16]],
        flags: u32,
    ) -> Result<Vec<(u32, u32)>, u32> {
        const VERTHYS_ERR_INVALID: u32 = 0x00000001;
        const ANCHOR_BATCH_MAX: usize = 64;

        if uuids.is_empty() || uuids.len() > ANCHOR_BATCH_MAX {
            return Err(VERTHYS_ERR_INVALID);
        }
        let mut flat = Vec::with_capacity(uuids.len() * 16);
        for uuid in uuids {
            flat.extend_from_slice(uuid);
        }
        let mut raw = vec![
            VerthysAnchorReleaseResultC {
                struct_size: std::mem::size_of::<VerthysAnchorReleaseResultC>() as u32,
                uuid: [0u8; 16],
                released: 0,
                cleanup_failed: 0,
                reserved: 0,
            };
            uuids.len()
        ];
        let mut produced: u32 = 0;
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysRollbackAnchorReleaseBatchFn> =
                match lib.get(b"Verthys_RollbackAnchorReleaseBatch") {
                    Ok(f) => f,
                    Err(_) => return Err(0xFFFFFFFF),
                };
            let rc = ffi_call(|| {
                func(
                    self.handle,
                    flat.as_ptr(),
                    uuids.len() as u32,
                    flags,
                    raw.as_mut_ptr(),
                    raw.len() as u32,
                    &mut produced,
                )
            })
            .unwrap_or(0xFFFFFFFF);
            if rc != VERTHYS_OK {
                return Err(rc);
            }
        }
        if produced as usize != uuids.len() {
            return Err(0xFFFFFFFF);
        }
        Ok(raw
            .iter()
            .map(|item| (item.released, item.cleanup_failed))
            .collect())
    }

    /// 合并并下发运行时守卫位（完整掩码语义）。
    ///
    /// 心跳位一旦由心跳线程置位便保持；挂起位跟随主进程下发值（停止守卫
    /// 下发 0）。合并结果写入进程级原子并立即通知 C 层，状态查询据此
    /// 区分"看门狗已接线"与"可修复缺口"。
    pub(crate) fn update_runtime_guards(&self, suspend_lock: bool) -> Result<(), u32> {
        let heartbeat = self.runtime_guards.load(Ordering::Relaxed) & 0x01;
        let next = heartbeat | if suspend_lock { 0x02 } else { 0 };
        self.runtime_guards.store(next, Ordering::Relaxed);
        self.push_runtime_guards()
    }

    /// 启用心跳线程（句柄由父进程 DuplicateHandle 注入本进程）。
    ///
    /// 独立线程每 500ms SetEvent，与 IPC 主循环解耦：即使主循环在执行长
    /// FFI（导入/轮换），脉冲仍持续，父进程可区分"忙"与"被挂起"。
    /// 成功后置 bit0 并通知 C 层；C 首次看到心跳位时刷新反注入线程基线
    ///（心跳线程起始地址在 worker EXE，不在 verthys.dll，必须纳入基线）。
    pub(crate) fn arm_heartbeat(&mut self, handle: u64) -> Result<(), u32> {
        if handle == 0 {
            return Err(VERTHYS_ERR_INVALID);
        }
        if self.heartbeat_thread.is_some() {
            return Ok(());
        }

        #[cfg(windows)]
        {
            let stop = Arc::new(AtomicBool::new(false));
            let stop_for_thread = stop.clone();
            let thread = std::thread::Builder::new()
                .name("verthys-heartbeat".into())
                .spawn(move || {
                    let h = handle as *mut std::ffi::c_void;
                    while !stop_for_thread.load(Ordering::Relaxed) {
                        unsafe {
                            let _ = SetEvent(h);
                        }
                        std::thread::sleep(Duration::from_millis(500));
                    }
                })
                .map_err(|_| 0xFFFFFFFFu32)?;
            self.heartbeat_stop = Some(stop);
            self.heartbeat_thread = Some(thread);
        }
        #[cfg(not(windows))]
        {
            return Err(0xFFFFFFFFu32);
        }

        let flags = self.runtime_guards.load(Ordering::Relaxed) | 0x01;
        self.runtime_guards.store(flags, Ordering::Relaxed);
        self.push_runtime_guards()
    }

    /// 将当前完整掩码推送到 C 层；旧 DLL 缺少该导出时仅诊断一次。
    fn push_runtime_guards(&self) -> Result<(), u32> {
        let flags = self.runtime_guards.load(Ordering::Relaxed);
        unsafe {
            let lib = &self._lib;
            let func: Symbol<VerthysNotifyRuntimeGuardsFn> =
                match lib.get(b"Verthys_NotifyRuntimeGuards") {
                    Ok(f) => f,
                    Err(_) => {
                        if !self.guards_symbol_warned.swap(true, Ordering::Relaxed) {
                            init_diag!(
                                "[worker] DLL 缺少 Verthys_NotifyRuntimeGuards（旧版），守卫位仅本地记录"
                            );
                        }
                        return Ok(());
                    }
                };
            let rc = ffi_call(|| { func(flags) }).unwrap_or(0xFFFFFFFF);
            if rc != VERTHYS_OK {
                return Err(rc);
            }
        }
        Ok(())
    }
}
