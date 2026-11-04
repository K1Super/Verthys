<#
 * tests/attack/VerthysHarness.psm1 — 攻击回归测试的原生 harness
 *
 * 职责边界：
 *   以“任意本地进程”的身份直接加载核心 DLL，模拟攻击者在应用之外调用
 *   Init/Create/Unlock/AddRecord/GetRecord/Lock。不依赖 Tauri、worker 或 UI，
 *   用于验证攻击面在 C 边界上的真实表现。
 *
 * 安全边界：
 *   - 所有测试容器一律生成或复制到独立临时目录，绝不改写调用方传入的副本。
 *   - 口令以 UTF-8 字节传入，避免 ANSI 代码页转换导致的口径漂移。
 *   - 明文扫描按块读取并保留跨块重叠，避免大文件整读占用内存。
 *   - 本模块不记录口令内容；日志只输出返回码与文件路径摘要。
#>
Set-StrictMode -Version Latest

$script:LegacyV3 = $false

function Initialize-VerthysNative {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$DllPath,
        [ValidateSet('Product', 'Legacy')][string]$Mode = 'Product'
    )

    if (-not (Test-Path -LiteralPath $DllPath -PathType Leaf)) {
        throw "核心 DLL 不存在: $DllPath"
    }
    $script:LegacyV3 = ($Mode -eq 'Legacy')
    $resolved = (Resolve-Path -LiteralPath $DllPath).Path

    if ('VerthysAttackNative' -as [type]) {
        return $resolved
    }

    $template = @'
using System;
using System.IO;
using System.Runtime.InteropServices;

public static class VerthysAttackNative
{
    public const string Dll = @"@@DLL@@";

    [StructLayout(LayoutKind.Sequential)]
    public struct Record
    {
        public int type;
        public IntPtr name;
        public UIntPtr name_len;
        public IntPtr data;
        public UIntPtr data_len;
    }

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int Verthys_Init(out IntPtr handle);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int Verthys_Deinit(IntPtr handle);

    [DllImport("kernel32", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryW(string path);

    [DllImport("kernel32", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);

    [DllImport("kernel32")]
    private static extern bool FreeLibrary(IntPtr module);

    /// 查询当前加载 DLL 是否导出指定符号（用于验证 v3 入口已从产品 DLL 移除）。
    public static bool HasExport(string name)
    {
        IntPtr module = LoadLibraryW(Dll);
        if (module == IntPtr.Zero) return false;
        try
        {
            return GetProcAddress(module, name) != IntPtr.Zero;
        }
        finally
        {
            FreeLibrary(module);
        }
    }

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    public static extern int Verthys_Lock(IntPtr handle);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int Verthys_CreateWithPreset(
        IntPtr handle,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        [MarshalAs(UnmanagedType.LPArray)] byte[] password,
        UIntPtr password_len,
        int preset);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int Verthys_Unlock(
        IntPtr handle,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        [MarshalAs(UnmanagedType.LPArray)] byte[] password,
        UIntPtr password_len,
        uint flags);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int Verthys_V4Create(
        IntPtr handle,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        [MarshalAs(UnmanagedType.LPArray)] byte[] password,
        UIntPtr password_len,
        byte[] recovery_text,
        UIntPtr recovery_cap);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int Verthys_V4Unlock(
        IntPtr handle,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        [MarshalAs(UnmanagedType.LPArray)] byte[] password,
        UIntPtr password_len);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int Verthys_AddRecord(
        IntPtr handle,
        ref Record record,
        out ulong id);

    [DllImport(Dll, CallingConvention = CallingConvention.Cdecl)]
    private static extern int Verthys_GetRecord(
        IntPtr handle,
        ulong id,
        out Record record);

    public static int Create(IntPtr handle, string path, byte[] password, int preset)
    {
        return Verthys_CreateWithPreset(handle, path, password,
            new UIntPtr((uint)password.Length), preset);
    }

    public static int CreateV4(IntPtr handle, string path, byte[] password,
        byte[] recoveryText)
    {
        return Verthys_V4Create(handle, path, password,
            new UIntPtr((uint)password.Length), recoveryText,
            new UIntPtr((uint)recoveryText.Length));
    }

    public static int Unlock(IntPtr handle, string path, byte[] password)
    {
        return Verthys_Unlock(handle, path, password,
            new UIntPtr((uint)password.Length), 0u);
    }

    public static int UnlockV4(IntPtr handle, string path, byte[] password)
    {
        return Verthys_V4Unlock(handle, path, password,
            new UIntPtr((uint)password.Length));
    }

    public static int AddRecord(IntPtr handle, int type, byte[] name, byte[] data)
    {
        IntPtr namePtr = Marshal.AllocHGlobal(name.Length == 0 ? 1 : name.Length);
        IntPtr dataPtr = Marshal.AllocHGlobal(data.Length == 0 ? 1 : data.Length);
        try
        {
            if (name.Length > 0) Marshal.Copy(name, 0, namePtr, name.Length);
            if (data.Length > 0) Marshal.Copy(data, 0, dataPtr, data.Length);

            Record record = new Record();
            record.type = type;
            record.name = namePtr;
            record.name_len = new UIntPtr((uint)name.Length);
            record.data = dataPtr;
            record.data_len = new UIntPtr((uint)data.Length);

            ulong id;
            return Verthys_AddRecord(handle, ref record, out id);
        }
        finally
        {
            Marshal.FreeHGlobal(namePtr);
            Marshal.FreeHGlobal(dataPtr);
        }
    }

    public static int GetRecordCode(IntPtr handle, ulong id)
    {
        Record record;
        return Verthys_GetRecord(handle, id, out record);
    }

    public static bool ContainsMarker(string path, byte[] marker)
    {
        if (marker == null || marker.Length == 0) return false;

        const int ChunkSize = 1 << 20;
        using (FileStream stream = new FileStream(path, FileMode.Open, FileAccess.Read,
                   FileShare.ReadWrite, ChunkSize, FileOptions.SequentialScan))
        {
            byte[] buffer = new byte[ChunkSize + marker.Length];
            int carry = 0;
            while (true)
            {
                int read = stream.Read(buffer, carry, ChunkSize);
                if (read <= 0) break;
                int total = carry + read;
                if (IndexOf(buffer, total, marker) >= 0) return true;
                carry = Math.Min(marker.Length - 1, total);
                Array.Copy(buffer, total - carry, buffer, 0, carry);
            }
        }
        return false;
    }

    private static int IndexOf(byte[] haystack, int length, byte[] needle)
    {
        int limit = length - needle.Length;
        for (int i = 0; i <= limit; i++)
        {
            bool matched = true;
            for (int j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j]) { matched = false; break; }
            }
            if (matched) return i;
        }
        return -1;
    }
}
'@

    $source = $template.Replace('@@DLL@@', $resolved)
    Add-Type -TypeDefinition $source -Language CSharp
    return $resolved
}

function New-Utf8Bytes {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text)
    # 逗号包裹防止空数组被输出管线展开为 $null，空口令探针需要真实的 byte[0]
    return , [System.Text.Encoding]::UTF8.GetBytes($Text)
}

function New-ContainerSecret {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    return [Convert]::ToBase64String($bytes)
}

function Open-VerthysHandle {
    $handle = [IntPtr]::Zero
    $rc = [VerthysAttackNative]::Verthys_Init([ref]$handle)
    if ($rc -ne 0) {
        throw "Verthys_Init 失败: rc=$rc"
    }
    return $handle
}

function Close-VerthysHandle {
    param([IntPtr]$Handle)
    if ($Handle -ne [IntPtr]::Zero) {
        [void][VerthysAttackNative]::Verthys_Deinit($Handle)
    }
}

function New-TestVault {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Password,
        [int]$Preset = 0,
        [hashtable[]]$Records = @()
    )

    if ($script:LegacyV3) {
        throw "Legacy 模式不得生成 v4 主样本；Baseline 必须使用 -Vault 历史样本"
    }
    $handle = Open-VerthysHandle
    try {
        # 恢复码缓冲 >= VTY_RECOVERY_TEXT_BUF；攻击回归不使用恢复通道。
        $recovery = New-Object byte[] 128
        $rc = [VerthysAttackNative]::CreateV4($handle, $Path, $Password, $recovery)
        if ($rc -ne 0) {
            throw "Verthys_V4Create 失败: rc=$rc"
        }

        $index = 0
        foreach ($record in $Records) {
            $nameBytes = New-Utf8Bytes -Text $record.Name
            $dataBytes = if ($record.Data -is [byte[]]) { $record.Data } else { New-Utf8Bytes -Text $record.Data }
            $rc = [VerthysAttackNative]::AddRecord($handle, [int]$record.Type, $nameBytes, $dataBytes)
            if ($rc -ne 0) {
                throw "Verthys_AddRecord 失败: index=$index rc=$rc"
            }
            $index++
        }

        $rc = [VerthysAttackNative]::Verthys_Lock($handle)
        if ($rc -ne 0) {
            throw "Verthys_Lock 失败: rc=$rc"
        }
    }
    finally {
        Close-VerthysHandle -Handle $handle
    }

    # 句柄释放后再读 magic：C 容器单写者锁会阻止 ReadAllBytes 的 FileShare.Read。
    $magic = [System.IO.File]::ReadAllBytes($Path)[0..3]
    $magicText = [System.Text.Encoding]::ASCII.GetString($magic)
    if ($magicText -ne 'VRTY') {
        throw "攻击主样本不是 v4 容器: magic=$magicText"
    }
}

function Add-TestRecordToVault {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Password,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Data
    )

    $handle = Open-VerthysHandle
    try {
        $rc = if ($script:LegacyV3) {
            [VerthysAttackNative]::Unlock($handle, $Path, $Password)
        } else {
            [VerthysAttackNative]::UnlockV4($handle, $Path, $Password)
        }
        if ($rc -ne 0) {
            return $rc
        }
        $rc = [VerthysAttackNative]::AddRecord($handle, 2, (New-Utf8Bytes -Text $Name), (New-Utf8Bytes -Text $Data))
        [void][VerthysAttackNative]::Verthys_Lock($handle)
        return $rc
    }
    finally {
        Close-VerthysHandle -Handle $handle
    }
}

function Test-VaultUnlock {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Password
    )

    $handle = Open-VerthysHandle
    try {
        if ($script:LegacyV3) {
            return [VerthysAttackNative]::Unlock($handle, $Path, $Password)
        }
        return [VerthysAttackNative]::UnlockV4($handle, $Path, $Password)
    }
    finally {
        Close-VerthysHandle -Handle $handle
    }
}

function Test-LockedRecordAccess {
    param([Parameter(Mandatory = $true)][string]$Path)

    $handle = Open-VerthysHandle
    try {
        return [VerthysAttackNative]::GetRecordCode($handle, 1)
    }
    finally {
        Close-VerthysHandle -Handle $handle
    }
}

function Get-MarkerHitFiles {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][byte[]]$Marker
    )

    $hits = New-Object System.Collections.Generic.List[string]
    Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
        if ([VerthysAttackNative]::ContainsMarker($_.FullName, $Marker)) {
            $hits.Add($_.FullName)
        }
    }
    return $hits
}

function Test-NativeExport {
    param([Parameter(Mandatory = $true)][string]$Name)
    return [VerthysAttackNative]::HasExport($Name)
}

function ConvertTo-VerthysResultName {
    param([int]$Code)
    switch ($Code) {
        0 { return 'OK' }
        1 { return 'INVALID' }
        2 { return 'AUTH' }
        3 { return 'NOTFOUND' }
        4 { return 'EXISTS' }
        5 { return 'FORMAT' }
        7 { return 'LOCKED' }
        8 { return 'IO' }
        9 { return 'CORRUPT' }
        10 { return 'RATE' }
        11 { return 'SNAPSHOT' }
        12 { return 'PEPPER_SOURCE' }
        default { return "UNKNOWN($Code)" }
    }
}

Export-ModuleMember -Function Initialize-VerthysNative, New-Utf8Bytes, New-ContainerSecret,
    New-TestVault, Add-TestRecordToVault, Test-VaultUnlock, Test-LockedRecordAccess,
    Get-MarkerHitFiles, Test-NativeExport, ConvertTo-VerthysResultName
