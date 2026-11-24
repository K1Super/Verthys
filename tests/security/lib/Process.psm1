# tests/security/lib/Process.psm1 — 子进程执行、超时与输出捕获。
#
# 统一用文件/异步流读取，避免 PowerShell 管道在孙进程继承句柄后无法返回 EOF。
# 超时终止整棵进程树，防止构建器或探针残留占用目录。

Set-StrictMode -Version Latest

function ConvertTo-SecurityArgumentString {
    param([string[]]$Arguments)

    $parts = New-Object System.Collections.Generic.List[string]
    foreach ($argument in @($Arguments)) {
        $value = [string]$argument
        if ($value -eq '') {
            $parts.Add('""')
            continue
        }
        if ($value -notmatch '[\s"]') {
            $parts.Add($value)
            continue
        }

        $builder = New-Object System.Text.StringBuilder
        [void]$builder.Append('"')
        $backslashes = 0
        foreach ($character in $value.ToCharArray()) {
            if ($character -eq '\') {
                $backslashes++
                continue
            }
            if ($character -eq '"') {
                [void]$builder.Append(('\' * ($backslashes * 2 + 1)))
                [void]$builder.Append('"')
                $backslashes = 0
                continue
            }
            if ($backslashes -gt 0) {
                [void]$builder.Append(('\' * $backslashes))
                $backslashes = 0
            }
            [void]$builder.Append($character)
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * ($backslashes * 2)))
        }
        [void]$builder.Append('"')
        $parts.Add($builder.ToString())
    }
    return ($parts -join ' ')
}

function Get-SecurityTaskText {
    param($Task)

    if ($null -eq $Task) { return '' }
    if ($Task.Wait(5000)) {
        try { return [string]$Task.Result }
        catch { return '' }
    }
    return ''
}

function Invoke-SecurityProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 600,
        [string]$WorkingDirectory = ''
    )

    $startedAt = Get-Date
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $FilePath
    $psi.Arguments = ConvertTo-SecurityArgumentString -Arguments $Arguments
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true
    # 子进程统一按 UTF-8 解码：Windows 默认按控制台代码页解释，会把
    # PowerShell 7 的中文输出解成乱码并污染 observed 文本。
    $psi.StandardOutputEncoding = New-Object System.Text.UTF8Encoding($false)
    $psi.StandardErrorEncoding = New-Object System.Text.UTF8Encoding($false)
    if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
        $psi.WorkingDirectory = $WorkingDirectory
    }

    $process = $null
    try {
        $process = [System.Diagnostics.Process]::Start($psi)
    }
    catch {
        return [pscustomobject]@{
            ExitCode    = -1
            StdOut      = ''
            StdErr      = ''
            TimedOut    = $false
            DurationMs  = [int]((Get-Date) - $startedAt).TotalMilliseconds
            CommandLine = ('{0} {1}' -f $FilePath, $psi.Arguments)
            Error       = $_.Exception.Message
        }
    }

    $stdoutTask = $process.StandardOutput.ReadToEndAsync()
    $stderrTask = $process.StandardError.ReadToEndAsync()
    $timedOut = $false
    if (-not $process.WaitForExit([Math]::Max(1, $TimeoutSeconds) * 1000)) {
        $timedOut = $true
        try {
            & taskkill.exe /PID $process.Id /T /F 2>&1 | Out-Null
        }
        catch {
            try { $process.Kill() } catch { }
        }
        [void]$process.WaitForExit(5000)
    }

    $stdout = Get-SecurityTaskText -Task $stdoutTask
    $stderr = Get-SecurityTaskText -Task $stderrTask
    $exitCode = if ($timedOut) { -1 } else { $process.ExitCode }
    $durationMs = [int]((Get-Date) - $startedAt).TotalMilliseconds
    $commandLine = '{0} {1}' -f $FilePath, $psi.Arguments
    $process.Dispose()

    return [pscustomobject]@{
        ExitCode    = $exitCode
        StdOut      = $stdout
        StdErr      = $stderr
        TimedOut    = $timedOut
        DurationMs  = $durationMs
        CommandLine = $commandLine
        Error       = $null
    }
}

function Invoke-SecurityPowerShellScript {
    <#
    .SYNOPSIS
    在独立 pwsh 中执行脚本，并强制子进程 stdout/stderr 使用 UTF-8。
    Windows 重定向时 Console.OutputEncoding 默认是 OEM 代码页，直接 -File
    调用会让中文观测文本变成乱码；这里在脚本执行前显式切换编码。
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ScriptPath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 600,
        [string]$WorkingDirectory = ''
    )

    $preamble = '[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); $OutputEncoding=[Console]::OutputEncoding; & '
    $command = $preamble + (ConvertTo-SecurityArgumentString -Arguments @($ScriptPath))
    $argumentText = ConvertTo-SecurityArgumentString -Arguments $Arguments
    if (-not [string]::IsNullOrWhiteSpace($argumentText)) {
        $command += ' ' + $argumentText
    }
    $command += '; if ($null -eq $LASTEXITCODE) { exit 0 } else { exit $LASTEXITCODE }'

    return Invoke-SecurityProcess -FilePath 'pwsh' `
        -Arguments @('-NoProfile', '-Command', $command) `
        -TimeoutSeconds $TimeoutSeconds -WorkingDirectory $WorkingDirectory
}

function Get-SecurityTextTail {
    [CmdletBinding()]
    param(
        [string]$Text,
        [int]$MaxLength = 600
    )

    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $normalized = ($Text -replace '\s+', ' ').Trim()
    if ($normalized.Length -le $MaxLength) { return $normalized }
    return ('...' + $normalized.Substring($normalized.Length - $MaxLength))
}

Export-ModuleMember -Function ConvertTo-SecurityArgumentString, Invoke-SecurityProcess,
Invoke-SecurityPowerShellScript, Get-SecurityTextTail
