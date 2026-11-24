# scripts/dev/dev_app_launcher.ps1 - cargo target runner for the signed dev host
#
# Cargo invokes this script with the freshly built host executable followed by
# application arguments. The script signs a copy named Verthys.exe next to the
# staged worker/DLL, then starts it inside a kill-on-close job object so the
# Tauri watcher cannot leave orphaned processes behind.
#
# ASCII only: Windows PowerShell 5.1 decodes BOM-less files with the ANSI code
# page, so localized comments can break parsing.

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 3.0

$repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
. (Join-Path $repoRoot "scripts\lib\release_signing.ps1")

$arguments = @($args)
if ($arguments.Count -lt 1) {
    throw "dev_app_launcher.ps1 requires the built host path as the first argument."
}
$builtHost = [string]$arguments[0]
$appArgs = @()
if ($arguments.Count -gt 1) {
    $appArgs = @($arguments[1..($arguments.Count - 1)])
}
if (-not (Test-Path -LiteralPath $builtHost -PathType Leaf)) {
    throw ("Built host not found: {0}" -f $builtHost)
}

$targetDebug = Join-Path $repoRoot "verthys-tauri\src-tauri\target\debug"
$stagedHost = Join-Path $targetDebug "Verthys.exe"
$stagedWorker = Join-Path $targetDebug "verthys-worker.exe"
$stagedDll = Join-Path $targetDebug "verthys.dll"
foreach ($file in @($stagedWorker, $stagedDll)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw ("Dev runtime staging is incomplete: {0}. Run build_dev.ps1 first." -f $file)
    }
}

$signing = Resolve-VerthysReleaseSigning -Required
if (-not $signing.Enabled) {
    throw "A code-signing certificate is required to start the dev host."
}
Assert-VerthysAuthenticodeSignature -Path $stagedWorker -ExpectedSha256 $signing.PublisherSha256 | Out-Null
Assert-VerthysAuthenticodeSignature -Path $stagedDll -ExpectedSha256 $signing.PublisherSha256 | Out-Null

# Stop only the dev instance that runs from the staged path; never touch the
# installed production Verthys.exe.
Get-Process -Name "Verthys" -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        if ($null -ne $_.Path -and ($_.Path -ieq $stagedHost)) {
            Stop-Process -Id $_.Id -Force -ErrorAction Stop
        }
    } catch {
    }
}

$staged = $false
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    try {
        Copy-Item -LiteralPath $builtHost -Destination $stagedHost -Force -ErrorAction Stop
        $staged = $true
        break
    } catch {
        if ($attempt -eq 19) {
            throw ("Cannot stage the signed dev host: {0}" -f $_.Exception.Message)
        }
        Start-Sleep -Milliseconds 250
    }
}
if (-not $staged) {
    throw "Cannot stage the signed dev host."
}

Invoke-VerthysAuthenticodeSign `
    -Path $stagedHost `
    -Certificate $signing.Certificate `
    -TimestampServer $signing.TimestampServer
Assert-VerthysAuthenticodeSignature -Path $stagedHost -ExpectedSha256 $signing.PublisherSha256 | Out-Null

# The machine budget bypass short-circuits kernel status queries in the C core;
# the signed dev runtime exercises the real service path instead.
Remove-Item Env:VERTHYS_TEST_MACHINE_LIMITER_BYPASS -ErrorAction SilentlyContinue

$jobType = @"
using System;
using System.Runtime.InteropServices;

public static class VerthysDevJob
{
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(IntPtr hJob, int infoClass, IntPtr info, uint infoLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static IntPtr CreateKillOnClose()
    {
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero)
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        info.BasicLimitInformation.LimitFlags = 0x2000;
        int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
        IntPtr buffer = Marshal.AllocHGlobal(length);
        try
        {
            Marshal.StructureToPtr(info, buffer, false);
            if (!SetInformationJobObject(job, 9, buffer, (uint)length))
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return job;
    }

    public static void Assign(IntPtr job, IntPtr process)
    {
        if (!AssignProcessToJobObject(job, process))
        {
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    public static void Close(IntPtr handle)
    {
        if (handle != IntPtr.Zero)
        {
            CloseHandle(handle);
        }
    }
}
"@
Add-Type -TypeDefinition $jobType -Language CSharp | Out-Null

$job = [VerthysDevJob]::CreateKillOnClose()
try {
    $parentPid = 0
    try {
        $parent = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $PID) -ErrorAction Stop
        if ($null -ne $parent) {
            $parentPid = [int]$parent.ParentProcessId
        }
    } catch {
    }

    $workingDirectory = Join-Path $repoRoot "verthys-tauri\src-tauri"
    $startArgs = @{
        FilePath         = $stagedHost
        WorkingDirectory = $workingDirectory
        PassThru         = $true
    }
    if ($appArgs.Count -gt 0) {
        $startArgs.ArgumentList = $appArgs
    }
    $process = Start-Process @startArgs
    try {
        [VerthysDevJob]::Assign($job, $process.Handle)
    } catch {
        try {
            Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
        } catch {
        }
        throw ("Failed to bind the dev host to the kill-on-close job: {0}" -f $_.Exception.Message)
    }

    while (-not $process.HasExited) {
        if ($parentPid -ne 0) {
            $parentAlive = Get-Process -Id $parentPid -ErrorAction SilentlyContinue
            if ($null -eq $parentAlive) {
                Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
                break
            }
        }
        Start-Sleep -Milliseconds 500
    }

    $process.Refresh()
    if ($process.HasExited) {
        exit $process.ExitCode
    }
    exit 0
} finally {
    [VerthysDevJob]::Close($job)
}
