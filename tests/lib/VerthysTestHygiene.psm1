# 测试卫生：隔离真实熔断/回退状态，并回收测试创建的 TPM 见证密钥。
#
# 为什么需要回收见证密钥：状态文件位置（旧 LOCALAPPDATA 路径或
# KnownFolder\Verthys\Security）不决定见证域；新代码的见证绑定设备根 +
# 用户 SID / 容器 UUID。测试每创建一个 库就可能留下见证密钥，长期复跑
# 会把 TPM 持久化键空间堆满。这里按“运行前快照 + 运行后差集”回收，
# 只删除本次测试新增的键，不触碰运行前已存在的真实用户见证。

if (-not ('VerthysWitnessStore' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public static class VerthysWitnessStore
{
    private const string ProviderName = "Microsoft Platform Crypto Provider";
    private const string WitnessPrefix = "VerthysWit_";
    private const uint NteNoMoreItems = 0x8009002AU;

    [StructLayout(LayoutKind.Sequential)]
    private struct KeyName
    {
        public IntPtr pszName;
        public IntPtr pszAlgId;
        public uint dwLegacyKeySpec;
        public uint dwFlags;
    }

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern uint NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, uint dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern uint NCryptEnumKeys(IntPtr hProvider, IntPtr pszScope, out IntPtr ppKeyName, ref IntPtr ppEnumState, uint dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern uint NCryptFreeBuffer(IntPtr pvInput);

    [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
    private static extern uint NCryptOpenKey(IntPtr hProvider, out IntPtr phKey, string pszKeyName, uint dwLegacyKeySpec, uint dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern uint NCryptDeleteKey(IntPtr hKey, uint dwFlags);

    [DllImport("ncrypt.dll")]
    private static extern uint NCryptFreeObject(IntPtr hObject);

    private static bool IsMissing(uint status)
    {
        return status == 0x80090011U || status == 0x80090016U || status == 0x80090026U;
    }

    public static string[] List()
    {
        IntPtr provider = IntPtr.Zero;
        uint rc = NCryptOpenStorageProvider(out provider, ProviderName, 0);
        if (rc != 0)
        {
            throw new InvalidOperationException("打开 " + ProviderName + " 失败: 0x" + rc.ToString("X8"));
        }

        IntPtr enumState = IntPtr.Zero;
        var names = new List<string>();
        try
        {
            while (true)
            {
                IntPtr keyNamePtr = IntPtr.Zero;
                rc = NCryptEnumKeys(provider, IntPtr.Zero, out keyNamePtr, ref enumState, 0);
                if (rc == NteNoMoreItems)
                {
                    break;
                }
                if (rc != 0)
                {
                    throw new InvalidOperationException("枚举 CNG 持久化键失败: 0x" + rc.ToString("X8"));
                }

                var keyName = (KeyName)Marshal.PtrToStructure(keyNamePtr, typeof(KeyName));
                string name = Marshal.PtrToStringUni(keyName.pszName);
                NCryptFreeBuffer(keyNamePtr);
                if (name != null && name.StartsWith(WitnessPrefix, StringComparison.Ordinal))
                {
                    names.Add(name);
                }
            }
        }
        finally
        {
            if (enumState != IntPtr.Zero)
            {
                NCryptFreeBuffer(enumState);
            }
            NCryptFreeObject(provider);
        }

        names.Sort(StringComparer.Ordinal);
        return names.ToArray();
    }

    public static uint Delete(string name)
    {
        if (name == null || !name.StartsWith(WitnessPrefix, StringComparison.Ordinal))
        {
            return 0x80090027U;
        }

        IntPtr provider = IntPtr.Zero;
        uint rc = NCryptOpenStorageProvider(out provider, ProviderName, 0);
        if (rc != 0)
        {
            return rc;
        }

        IntPtr key = IntPtr.Zero;
        rc = NCryptOpenKey(provider, out key, name, 0, 0);
        if (rc != 0)
        {
            NCryptFreeObject(provider);
            return IsMissing(rc) ? 0U : rc;
        }

        rc = NCryptDeleteKey(key, 0);
        if (rc != 0)
        {
            NCryptFreeObject(key);
        }
        NCryptFreeObject(provider);
        return rc;
    }
}
'@
}

function Get-VerthysWitnessNames {
    <#
    .SYNOPSIS
    返回当前用户下全部 Verthys 见证密钥名称（只读）。
    #>
    return @([VerthysWitnessStore]::List())
}

function Get-VerthysRealAnchorFingerprint {
    <#
    .SYNOPSIS
    计算真实熔断/回退状态文件的联合指纹；文件不存在记 missing。
    覆盖旧路径与 KnownFolder\Verthys\Security 新路径，必须在脚本改写
    LOCALAPPDATA 之前调用。
    #>
    [CmdletBinding()]
    param(
        [string]$LocalAppData = $env:LOCALAPPDATA
    )

    $paths = @(
        (Join-Path $LocalAppData 'Verthys/rollback.state'),
        (Join-Path $LocalAppData 'Verthys/lockout.state'),
        (Join-Path $LocalAppData 'Verthys/Security/rollback.state'),
        (Join-Path $LocalAppData 'Verthys/Security/lockout.state')
    )
    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($statePath in $paths) {
        if (-not (Test-Path -LiteralPath $statePath)) {
            $parts.Add("$statePath=missing")
            continue
        }
        $hash = (Get-FileHash -LiteralPath $statePath -Algorithm SHA256).Hash
        $parts.Add("$statePath=sha256:$hash")
    }
    return ($parts -join '|')
}

function Start-VerthysTestHygiene {
    <#
    .SYNOPSIS
    在测试开始前记录真实锚点指纹与见证密钥快照。
    #>
    [CmdletBinding()]
    param(
        [string]$LocalAppData = $env:LOCALAPPDATA
    )

    $witnessSupported = $true
    $witnessNames = @()
    try {
        $witnessNames = @(Get-VerthysWitnessNames)
    } catch {
        # 无 TPM / CNG 平台提供程序不可用时不能阻断测试本身；此类环境
        # 也不会产生见证密钥，只需把回收能力标记为不可用并留痕。
        $witnessSupported = $false
        Write-Warning "CNG 见证密钥枚举不可用，跳过回收：$($_.Exception.Message)"
    }

    return [pscustomobject]@{
        LocalAppData      = $LocalAppData
        AnchorFingerprint = Get-VerthysRealAnchorFingerprint -LocalAppData $LocalAppData
        WitnessNames      = $witnessNames
        WitnessSupported  = $witnessSupported
        Completed         = $false
    }
}

function Complete-VerthysTestHygiene {
    <#
    .SYNOPSIS
    回收本次测试新增的见证密钥，并确认真实锚点状态未被测试改写。
    幂等：同一 Scope 重复调用不会重复执行。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Scope
    )

    if ($null -eq $Scope -or $Scope.Completed) {
        return
    }
    $Scope.Completed = $true

    $before = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($name in @($Scope.WitnessNames)) {
        if (-not [string]::IsNullOrEmpty($name)) { [void]$before.Add($name) }
    }

    $removed = 0
    $failures = @()
    if ($Scope.WitnessSupported) {
        foreach ($name in @(Get-VerthysWitnessNames)) {
            if ($before.Contains($name)) { continue }
            $rc = [VerthysWitnessStore]::Delete($name)
            if ($rc -eq 0) {
                $removed++
            } else {
                $failures += ('{0}:0x{1:X8}' -f $name, $rc)
            }
        }
    }

    if ($removed -gt 0) {
        Write-Host "[hygiene] 已回收测试见证密钥 $removed 个"
    }

    $after = Get-VerthysRealAnchorFingerprint -LocalAppData $Scope.LocalAppData
    if ($after -ne $Scope.AnchorFingerprint) {
        throw ("测试污染了真实熔断/回退状态（旧路径或 Verthys\Security）：$($Scope.LocalAppData)`n" +
            "before=$($Scope.AnchorFingerprint)`nafter=$after")
    }
    if ($failures.Count -gt 0) {
        throw "见证密钥回收失败：$($failures -join '; ')"
    }
}

Export-ModuleMember -Function Get-VerthysWitnessNames, Get-VerthysRealAnchorFingerprint, Start-VerthysTestHygiene, Complete-VerthysTestHygiene
