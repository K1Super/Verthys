; syscall_thunk_x64.asm — ACG 兼容的直连系统调用 thunk（x64，MSVC）
;
; 职责：
;   在 DLL 映像内提供固定的 syscall 指令序列；SSN 由可写数据槽在初始化时写入。
;   不使用运行期分配的可执行内存，因此在 ACG（禁止动态代码）下仍可激活。
;
; 约束：
;   - 仅由 syscall_direct.c 在激活后直接调用，不作为导出符号。
;   - 调用约定为 Microsoft x64：前四参数位于 rcx/rdx/r8/r9，第五参数位于栈。
;   - r10 承载首个参数副本，eax 承载 SSN，与内核系统调用入口约定一致。
;   - 代码段只读，数据槽可写；不存在可写可执行页。
;   - 每个目标一个 thunk 与一个 SSN 槽，槽位顺序与 syscall_direct.c 的目标表一致。
;
; 线程安全：
;   SSN 槽只在 InitOnce 初始化期间写入；写入完成后以完全屏障发布激活标志，
;   此后所有线程只读，无需额外同步。

.data
PUBLIC verthys_scd_ssn0
verthys_scd_ssn0 DWORD 0
PUBLIC verthys_scd_ssn1
verthys_scd_ssn1 DWORD 0

.code
PUBLIC verthys_scd_thunk0
verthys_scd_thunk0 PROC
    mov r10, rcx
    mov eax, DWORD PTR [verthys_scd_ssn0]
    syscall
    ret
verthys_scd_thunk0 ENDP

PUBLIC verthys_scd_thunk1
verthys_scd_thunk1 PROC
    mov r10, rcx
    mov eax, DWORD PTR [verthys_scd_ssn1]
    syscall
    ret
verthys_scd_thunk1 ENDP

END
