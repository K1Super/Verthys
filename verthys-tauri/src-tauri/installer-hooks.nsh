; installer-hooks.nsh — Verthys perMachine 安装器的服务生命周期钩子
;
; 应用安装包与 SYSTEM 服务在同一提权安装流程内完成：
;   PREINSTALL  阻断旧 perUser 安装，记录全新/升级状态
;   POSTINSTALL 从 service-payload 调用服务 exe /install /quiet
;   PREUNINSTALL 调用 /uninstall /quiet，失败即中止，避免半删
;   POSTUNINSTALL 清理注册表残留并复核
;
; 服务源目录 service-payload 与服务安装目录 SecurityService 不同，
; 运行中的服务 exe 不会被应用文件覆盖；所有调用均在管理员上下文执行。

Var VerthysInstallStarted
Var VerthysServiceInstalled
Var VerthysFreshInstall

; MUI 的 .onUserAbort 通过 MUI_CUSTOMFUNCTION_ABORT 回调扩展，不能重复定义。
!define MUI_CUSTOMFUNCTION_ABORT "VerthysOnUserAbort"

!macro NSIS_HOOK_PREINSTALL
  StrCpy $VerthysInstallStarted 0
  StrCpy $VerthysServiceInstalled 0
  StrCpy $VerthysFreshInstall 0

  ; 旧 perUser 安装与新 perMachine 安装不能共存；检测到则零写入退出。
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCTNAME}" "UninstallString"
  ${If} $0 != ""
    IfFileExists "$INSTDIR\${MAINBINARYNAME}.exe" verthys_legacy_keep_install
      RMDir "$INSTDIR"
    verthys_legacy_keep_install:
    MessageBox MB_ICONSTOP "检测到旧版按用户安装。请先卸载旧版 Verthys，再安装当前版本。"
    SetErrorLevel 3
    Quit
  ${EndIf}

  ReadRegStr $0 HKLM "${UNINSTKEY}" ""
  ${If} $0 == ""
    StrCpy $VerthysFreshInstall 1
  ${EndIf}

  ; 清理旧 perUser 安装遗留的 HKCU 安装位置/语言键；新 perMachine 包只写 HKLM。
  DeleteRegKey HKCU "${MANUPRODUCTKEY}"
  DeleteRegKey /ifempty HKCU "${MANUKEY}"

  StrCpy $VerthysInstallStarted 1
!macroend

!macro NSIS_HOOK_POSTINSTALL
  nsExec::ExecToStack '"$INSTDIR\service-payload\VerthysSecuritySvc.exe" /install /quiet'
  Pop $0
  Pop $1
  ${If} $0 == 0
    ReadRegDWORD $2 HKLM "SOFTWARE\Verthys\SecurityService" "Installed"
    ${If} $2 != 1
      StrCpy $0 5
    ${EndIf}
  ${EndIf}

  ${If} $0 != 0
    ${If} $VerthysFreshInstall == 1
      Call VerthysRollbackFreshInstall
      MessageBox MB_ICONSTOP "安全服务安装失败（退出码 $0）。本次安装已回滚，系统未留下残留。"
    ${Else}
      MessageBox MB_ICONSTOP "安全服务升级失败（退出码 $0）。请重新运行安装程序修复。"
    ${EndIf}
    SetErrorLevel 5
    Abort
  ${EndIf}
  StrCpy $VerthysServiceInstalled 1
  StrCpy $VerthysInstallStarted 0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  ; 机器密钥材料保护：container.secret 由 DPAPI 绑定当前用户，是打开既有
  ; 加密库的设备槽密钥材料。应用数据目录会在勾选 “Delete the application
  ; data” 时被整目录删除，因此必须在删除前把它转移到不受卸载影响的
  ; %LOCALAPPDATA%\Verthys\KeyMaterial；复制失败即中止卸载，宁可保留安装，
  ; 也不让用户的加密库永久无法打开。
  SetShellVarContext current
  ${IfNot} ${FileExists} "$LOCALAPPDATA\Verthys\KeyMaterial\container.secret"
    ${If} ${FileExists} "$LOCALAPPDATA\com.verthys.app\container.secret"
      CreateDirectory "$LOCALAPPDATA\Verthys\KeyMaterial"
      CopyFiles /SILENT "$LOCALAPPDATA\com.verthys.app\container.secret" "$LOCALAPPDATA\Verthys\KeyMaterial\container.secret"
      ${IfNot} ${FileExists} "$LOCALAPPDATA\Verthys\KeyMaterial\container.secret"
        MessageBox MB_ICONSTOP|MB_OK "无法保留本机密钥材料，卸载已中止，以免已有加密库永久无法打开。请检查磁盘空间与权限后重试。" /SD IDOK
        SetErrorLevel 5
        Quit
      ${EndIf}
    ${EndIf}
  ${EndIf}

  ; 勾选删除应用数据时明确告知：应用数据会删除，但密钥材料必须保留。
  ${If} $DeleteAppDataCheckboxState = 1
    MessageBox MB_ICONINFORMATION|MB_OK "应用数据将被删除；为保护已有加密库，本机密钥材料会保留在 %LOCALAPPDATA%\Verthys\KeyMaterial。" /SD IDOK
  ${EndIf}

  ; 先停服务并清理机器状态；失败时立即中止，应用文件尚未删除。
  nsExec::ExecToStack '"$INSTDIR\service-payload\VerthysSecuritySvc.exe" /uninstall /quiet'
  Pop $0
  Pop $1
  ${If} $0 != 0
    IfFileExists "$INSTDIR\service-payload\VerthysSecuritySvc.exe" 0 verthys_uninstall_fallback
    MessageBox MB_ICONSTOP "安全服务卸载失败（退出码 $0）。应用未被删除，请重试或联系支持。"
    SetErrorLevel 5
    Quit
    verthys_uninstall_fallback:
      nsExec::ExecToStack '"$SYSDIR\sc.exe" stop VerthysSecuritySvc'
      Pop $0
      nsExec::ExecToStack '"$SYSDIR\sc.exe" delete VerthysSecuritySvc'
      Pop $0
      ReadRegStr $2 HKLM "SYSTEM\CurrentControlSet\Services\VerthysSecuritySvc" "ImagePath"
      ${If} $2 != ""
        MessageBox MB_ICONSTOP "安全服务删除失败，应用保持安装状态。"
        SetErrorLevel 5
        Quit
      ${EndIf}
      RMDir /r "$INSTDIR\SecurityService"
      DeleteRegKey HKLM "SOFTWARE\Verthys\SecurityService"
      DeleteRegKey HKLM "SYSTEM\CurrentControlSet\Services\EventLog\Application\VerthysSecuritySvc"
      RMDir /r "$PROGRAMDATA\Verthys"
  ${EndIf}

  ; 服务锚点必须已消失；否则防止删除应用后留下半装服务。
  ReadRegDWORD $2 HKLM "SOFTWARE\Verthys\SecurityService" "Installed"
  ${If} $2 == 1
    MessageBox MB_ICONSTOP "安全服务仍处于已安装状态，卸载已中止。"
    SetErrorLevel 5
    Quit
  ${EndIf}
  RMDir /r "$INSTDIR\SecurityService"
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  DeleteRegKey HKLM "${MANUPRODUCTKEY}"
  DeleteRegKey /ifempty HKLM "${MANUKEY}"
  DeleteRegValue HKCU "${MANUPRODUCTKEY}" "Installer Language"
  DeleteRegKey /ifempty HKCU "${MANUPRODUCTKEY}"
  DeleteRegKey /ifempty HKCU "${MANUKEY}"

  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Services\VerthysSecuritySvc" "ImagePath"
  ${If} $0 != ""
    SetErrorLevel 5
  ${EndIf}
  IfFileExists "$PROGRAMDATA\Verthys\*.*" 0 verthys_state_clean
    SetErrorLevel 5
  verthys_state_clean:
!macroend

Function VerthysRollbackFreshInstall
  ${If} $VerthysServiceInstalled == 1
    nsExec::ExecToStack '"$INSTDIR\service-payload\VerthysSecuritySvc.exe" /uninstall /quiet'
    Pop $0
    Pop $1
  ${EndIf}

  Delete "$DESKTOP\${PRODUCTNAME}.lnk"
  Delete "$SMPROGRAMS\${PRODUCTNAME}.lnk"
  RMDir /r "$SMPROGRAMS\${PRODUCTNAME}"
  DeleteRegKey HKLM "${UNINSTKEY}"
  DeleteRegKey HKLM "${MANUPRODUCTKEY}"
  DeleteRegKey /ifempty HKLM "${MANUKEY}"
  DeleteRegValue HKCU "${MANUPRODUCTKEY}" "Installer Language"
  DeleteRegKey /ifempty HKCU "${MANUPRODUCTKEY}"
  DeleteRegKey /ifempty HKCU "${MANUKEY}"
  RMDir /r "$INSTDIR"

  StrCpy $VerthysServiceInstalled 0
  StrCpy $VerthysInstallStarted 0
FunctionEnd

Function VerthysOnUserAbort
  ${If} $VerthysInstallStarted == 1
  ${AndIf} $VerthysFreshInstall == 1
    Call VerthysRollbackFreshInstall
  ${EndIf}
FunctionEnd

Function .onInstFailed
  ${If} $VerthysInstallStarted == 1
  ${AndIf} $VerthysFreshInstall == 1
    Call VerthysRollbackFreshInstall
  ${EndIf}
FunctionEnd
