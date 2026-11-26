# scripts/lib/build_lock.ps1 - repository-scoped build pipeline lock
#
# ASCII only: Windows PowerShell 5.1 decodes BOM-less files with the ANSI code
# page, so localized text can break parsing.
#
# A named mutex serializes the production pipeline against dev staging. Both
# write the shared packaging paths, so an interleaved dev staging can replace
# production assets while the production build is bundling or verifying.
#
# The mutex is released automatically when the owner process exits (including
# crashes); the metadata file records the current owner so the blocked side can
# report who holds the lock. Mutex name and metadata path derive from a hash of
# the repository path, so independent checkouts do not collide.

function Get-VerthysBuildLockIdentity {
    param([Parameter(Mandatory = $true)][string]$Root)

    $full = [System.IO.Path]::GetFullPath($Root).TrimEnd('\').ToLowerInvariant()
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($full))
        $hex = (($digest | ForEach-Object { $_.ToString("x2") }) -join "").Substring(0, 16)
    } finally {
        $sha.Dispose()
    }

    return [pscustomobject]@{
        MutexName = "Local\Verthys.BuildPipeline." + $hex
        MetaPath  = (Join-Path ([System.IO.Path]::GetTempPath()) ("verthys-build-lock-" + $hex + ".json"))
    }
}

function Enter-VerthysBuildLock {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][ValidateSet("production", "dev")][string]$Role
    )

    $identity = Get-VerthysBuildLockIdentity -Root $Root
    $mutex = New-Object System.Threading.Mutex($false, $identity.MutexName)
    $acquired = $false
    try {
        $acquired = $mutex.WaitOne(0)
    } catch [System.Threading.AbandonedMutexException] {
        # Previous owner died without releasing; ownership passes to us.
        $acquired = $true
    }

    if (-not $acquired) {
        $owner = ""
        if (Test-Path -LiteralPath $identity.MetaPath -PathType Leaf) {
            try {
                $meta = Get-Content -LiteralPath $identity.MetaPath -Raw -ErrorAction Stop |
                    ConvertFrom-Json -ErrorAction Stop
                $owner = (" (owner: role={0}, pid={1}, started={2})" -f $meta.role, $meta.pid, $meta.started_at)
            } catch {
                $owner = " (owner metadata unreadable)"
            }
        }
        $mutex.Dispose()
        throw ("another build pipeline is active{0}; wait for it to finish or close the dev session" -f $owner)
    }

    $meta = [ordered]@{
        schema     = 1
        role       = $Role
        pid        = $PID
        started_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        root       = [System.IO.Path]::GetFullPath($Root)
    }
    [System.IO.File]::WriteAllText(
        $identity.MetaPath,
        ($meta | ConvertTo-Json -Depth 4),
        (New-Object System.Text.UTF8Encoding($false)))

    return [pscustomobject]@{
        Mutex    = $mutex
        MetaPath = $identity.MetaPath
        Role     = $Role
    }
}

function Exit-VerthysBuildLock {
    param([Parameter(Mandatory = $false)]$Lock)

    if ($null -eq $Lock) { return }
    try {
        if (Test-Path -LiteralPath $Lock.MetaPath -PathType Leaf) {
            Remove-Item -LiteralPath $Lock.MetaPath -Force -ErrorAction SilentlyContinue
        }
    } finally {
        try { $Lock.Mutex.ReleaseMutex() } catch { }
        $Lock.Mutex.Dispose()
    }
}
