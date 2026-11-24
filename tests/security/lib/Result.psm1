# tests/security/lib/Result.psm1 — 统一结果模型、状态策略与证据输出。
#
# 状态语义：
#   PASS     断言全部满足
#   FAIL     断言失败
#   SKIP     显式前置不满足，仅 dev/standard 容忍
#   BLOCKED  外部证据或平台能力缺失，release 不容忍
#   ERROR    执行器异常或输出不可解析，任何 profile 都失败
#   NOT_RUN  profile/执行器未产生结果，release 必需项视为失败
#
# 退出码：
#   0 成功；1 存在 FAIL/ERROR；2 注册表/schema/未知 ID/重复结果；3 release 必需项非 PASS

Set-StrictMode -Version Latest

$script:AllowedStatuses = @('PASS', 'FAIL', 'SKIP', 'BLOCKED', 'ERROR', 'NOT_RUN')

function New-SecurityRunContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Registry,
        [Parameter(Mandatory = $true)][string]$Profile,
        [Parameter(Mandatory = $true)][string]$Suite,
        [Parameter(Mandatory = $true)][string]$Mode,
        [Parameter(Mandatory = $true)][string]$OutDir,
        [Parameter(Mandatory = $true)][string]$RepoRoot,
        [Parameter(Mandatory = $true)]$Metadata,
        [Parameter(Mandatory = $true)][string]$WorkDir,
        [string[]]$CaseIds = $null
    )

    $selected = if ($null -ne $CaseIds) {
        @($CaseIds | ForEach-Object { $Registry.ById[[string]$_] }
            | Where-Object { $null -ne $_ })
    }
    else {
        @(Resolve-SecurityCaseSelection -Registry $Registry -Suite $Suite -Profile $Profile)
    }
    $timestamp = (Get-Date).ToUniversalTime()
    $suffix = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $runId = '{0}-{1}' -f $timestamp.ToString('yyyyMMddTHHmmssZ'), $suffix

    return [pscustomobject]@{
        SchemaVersion = 1
        RunId         = $runId
        Timestamp     = $timestamp.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Profile       = $Profile
        Suite         = $Suite
        Mode          = $Mode
        OutDir        = $OutDir
        RepoRoot      = $RepoRoot
        WorkDir       = $WorkDir
        Registry      = $Registry
        CasesById     = $Registry.ById
        SelectedIds   = @($selected | ForEach-Object { [string]$_.id })
        RequiredIds   = @(Get-SecurityRequiredCaseIds -Registry $Registry -Profile $Profile)
        Metadata      = $Metadata
        Results       = New-Object System.Collections.Generic.List[object]
        Errors        = New-Object System.Collections.Generic.List[string]
        StartedAt     = $timestamp
    }
}

function Add-SecurityCaseResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]$Context,
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Status,
        [string]$Expected,
        [string]$Observed,
        [string]$Evidence,
        [int]$DurationMs = 0,
        $ExecutorExit = $null
    )

    $caseId = $Id.Trim()
    if (-not $Context.CasesById.ContainsKey($caseId)) {
        $Context.Errors.Add("未知用例 ID: $caseId")
        return
    }
    if (-not ($Context.SelectedIds -contains $caseId)) {
        $Context.Errors.Add("用例不在当前运行范围: $caseId")
        return
    }

    $normalized = $Status.Trim().ToUpperInvariant()
    if ($AllowedStatuses -notcontains $normalized) {
        $Context.Errors.Add("用例 $caseId 返回非法状态: $Status")
        return
    }

    $expectedText = if ([string]::IsNullOrWhiteSpace($Expected)) { '' } else { $Expected.Trim() }
    $observedText = if ([string]::IsNullOrWhiteSpace($Observed)) { '' } else { $Observed.Trim() }
    if ($expectedText -eq '' -or $observedText -eq '') {
        $missing = if ($expectedText -eq '') { 'expected' } else { 'observed' }
        $normalized = 'ERROR'
        $observedText = "结果缺少 $missing；原始 observed=$observedText"
        if ($expectedText -eq '') { $expectedText = '未提供' }
    }

    $existing = @($Context.Results | Where-Object { $_.id -eq $caseId }) | Select-Object -First 1
    if ($null -ne $existing) {
        $Context.Errors.Add("重复结果 ID: $caseId")
        $existing.status = 'ERROR'
        $existing.observed = '同一用例被返回多次，结果不可信'
        return
    }

    $case = $Context.CasesById[$caseId]
    $Context.Results.Add([pscustomobject]@{
            id           = $caseId
            legacyId     = [string]$case.legacyId
            name         = [string]$case.name
            suite        = [string]$case.suite
            severity     = [string]$case.severity
            requirement  = [string]$case.requirement
            kind         = [string]$case.kind
            status       = $normalized
            expected     = $expectedText
            observed     = $observedText
            evidence     = $(if ([string]::IsNullOrWhiteSpace($Evidence)) { $null } else { $Evidence })
            durationMs   = [Math]::Max(0, [int]$DurationMs)
            executorExit = $(if ($null -eq $ExecutorExit) { $null } else { [int]$ExecutorExit })
        })
}

function ConvertTo-SecurityStatus {
    <#
    .SYNOPSIS
    把既有执行器的 verdict 归一化为统一状态。
    SKELETON/KNOWN_GAP 对证据类用例表示证据缺失（BLOCKED），其余表示未执行（SKIP）。
    #>
    [CmdletBinding()]
    param(
        [string]$Verdict,
        [string]$Kind = 'behavioral'
    )

    switch -Regex ($Verdict.Trim().ToUpperInvariant()) {
        '^PASS$' { return 'PASS' }
        '^FAIL$' { return 'FAIL' }
        '^SKIP$' { return 'SKIP' }
        '^BLOCKED$' { return 'BLOCKED' }
        '^ERROR$' { return 'ERROR' }
        '^(SKELETON|KNOWN_GAP)$' {
            if ($Kind -eq 'evidence') { return 'BLOCKED' }
            return 'SKIP'
        }
        default { return 'ERROR' }
    }
}

function Get-SecurityCaseRows {
    <#
    .SYNOPSIS
    按选中用例顺序返回结果行；执行器未返回的用例补 NOT_RUN。
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context)

    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($caseId in $Context.SelectedIds) {
        $existing = @($Context.Results | Where-Object { $_.id -eq $caseId }) | Select-Object -First 1
        if ($null -ne $existing) {
            $rows.Add($existing)
            continue
        }
        $case = $Context.CasesById[$caseId]
        $rows.Add([pscustomobject]@{
                id           = $caseId
                legacyId     = [string]$case.legacyId
                name         = [string]$case.name
                suite        = [string]$case.suite
                severity     = [string]$case.severity
                requirement  = [string]$case.requirement
                kind         = [string]$case.kind
                status       = 'NOT_RUN'
                expected     = '本轮应执行该用例'
                observed     = '执行器未返回该用例结果'
                evidence     = $null
                durationMs   = 0
                executorExit = $null
            })
    }
    return $rows.ToArray()
}

function Get-SecuritySummary {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context)

    $rows = @(Get-SecurityCaseRows -Context $Context)
    $required = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
    foreach ($id in @($Context.RequiredIds)) { [void]$required.Add([string]$id) }

    $summary = [ordered]@{
        total            = $rows.Count
        pass             = 0
        fail             = 0
        skip             = 0
        blocked          = 0
        error            = 0
        notRun           = 0
        requiredFailures = 0
        behavioral       = 0
        static           = 0
        evidence         = 0
        control          = 0
    }
    foreach ($row in $rows) {
        switch ($row.status) {
            'PASS' { $summary.pass++ }
            'FAIL' { $summary.fail++ }
            'SKIP' { $summary.skip++ }
            'BLOCKED' { $summary.blocked++ }
            'ERROR' { $summary.error++ }
            'NOT_RUN' { $summary.notRun++ }
        }
        switch ($row.kind) {
            'behavioral' { $summary.behavioral++ }
            'static' { $summary.static++ }
            'evidence' { $summary.evidence++ }
            'control' { $summary.control++ }
        }
        if ($required.Contains([string]$row.id) -and $row.status -ne 'PASS') {
            $summary.requiredFailures++
        }
    }
    return [pscustomobject]$summary
}

function Get-SecurityExitCode {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context)

    if ($Context.Errors.Count -gt 0) { return 2 }

    $summary = Get-SecuritySummary -Context $Context
    if ($summary.fail -gt 0 -or $summary.error -gt 0) { return 1 }

    if (($Context.Profile -eq 'release' -or $Context.Profile -eq 'baseline') -and
        $summary.requiredFailures -gt 0) {
        return 3
    }
    return 0
}

function Get-SecurityResultDocument {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context)

    $metadata = $Context.Metadata
    $summary = Get-SecuritySummary -Context $Context
    $caseDocuments = New-Object System.Collections.Generic.List[object]
    foreach ($row in @(Get-SecurityCaseRows -Context $Context)) {
        $caseDocuments.Add([ordered]@{
                id           = [string]$row.id
                legacyId     = $(if ($null -eq $row.legacyId -or [string]$row.legacyId -eq '') { $null } else { [string]$row.legacyId })
                name         = [string]$row.name
                suite        = [string]$row.suite
                severity     = [string]$row.severity
                requirement  = [string]$row.requirement
                kind         = [string]$row.kind
                status       = [string]$row.status
                expected     = [string]$row.expected
                observed     = [string]$row.observed
                evidence     = $(if ([string]::IsNullOrWhiteSpace([string]$row.evidence)) { $null } else { [string]$row.evidence })
                durationMs   = [int]$row.durationMs
                executorExit = $(if ($null -eq $row.executorExit) { $null } else { [int]$row.executorExit })
            })
    }

    return [ordered]@{
        schemaVersion = 1
        runId         = [string]$Context.RunId
        timestamp     = [string]$Context.Timestamp
        profile       = [string]$Context.Profile
        suite         = [string]$Context.Suite
        mode          = [string]$Context.Mode
        metadata      = [ordered]@{
            gitCommit     = $(if ($null -eq $metadata.gitCommit) { $null } else { [string]$metadata.gitCommit })
            gitDirty      = $(if ($null -eq $metadata.gitDirty) { $null } else { [bool]$metadata.gitDirty })
            osBuild       = [string]$metadata.osBuild
            powershell    = [string]$metadata.powershell
            dllSha256     = $(if ([string]::IsNullOrWhiteSpace([string]$metadata.dllSha256)) { $null } else { [string]$metadata.dllSha256 })
            workerSha256  = $(if ([string]::IsNullOrWhiteSpace([string]$metadata.workerSha256)) { $null } else { [string]$metadata.workerSha256 })
            serviceSha256 = $(if ([string]::IsNullOrWhiteSpace([string]$metadata.serviceSha256)) { $null } else { [string]$metadata.serviceSha256 })
            registrySha256 = [string]$metadata.registrySha256
        }
        summary       = [ordered]@{
            total            = [int]$summary.total
            pass             = [int]$summary.pass
            fail             = [int]$summary.fail
            skip             = [int]$summary.skip
            blocked          = [int]$summary.blocked
            error            = [int]$summary.error
            notRun           = [int]$summary.notRun
            requiredFailures = [int]$summary.requiredFailures
            behavioral       = [int]$summary.behavioral
            static           = [int]$summary.static
            evidence         = [int]$summary.evidence
            control          = [int]$summary.control
        }
        cases         = $caseDocuments.ToArray()
        errors        = $Context.Errors.ToArray()
    }
}

function Get-SecurityDocumentValue {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    $value = $null
    if ($Object -is [System.Collections.IDictionary]) {
        if (-not $Object.Contains($Name)) { return $null }
        $value = $Object[$Name]
    }
    else {
        $property = $Object.PSObject.Properties[$Name]
        if ($null -eq $property) { return $null }
        $value = $property.Value
    }
    # 数组成员必须作为单个对象返回，否则单元素数组会被管道展开成标量，
    # 让“cases 必须为数组”这类结构校验产生假失败。
    if ($value -is [System.Array]) { return , $value }
    return $value
}

function Get-SecurityDocumentKeys {
    param($Object)
    if ($Object -is [System.Collections.IDictionary]) { return @($Object.Keys) }
    return @($Object.PSObject.Properties | ForEach-Object { $_.Name })
}

function Test-SecurityDocumentHasProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    if ($Object -is [System.Collections.IDictionary]) { return $Object.Contains($Name) }
    return ($null -ne $Object.PSObject.Properties[$Name])
}

function Test-SecurityObjectShape {
    param($Object, [string[]]$Required, [string[]]$Allowed, [string]$Label, $Errors)
    if ($null -eq $Object) {
        $Errors.Add("$Label 不是对象")
        return $false
    }
    foreach ($name in $Required) {
        if (-not (Test-SecurityDocumentHasProperty $Object $name)) {
            $Errors.Add("$Label 缺少字段 $name")
        }
    }
    foreach ($name in @(Get-SecurityDocumentKeys $Object)) {
        if ($Allowed -notcontains [string]$name) {
            $Errors.Add("$Label 含未声明字段 $name")
        }
    }
    return $true
}

function Test-SecurityResultDocument {
    <#
    .SYNOPSIS
    与 schema/result.schema.json 对齐的结构校验；不依赖外部 JSON Schema 库。
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Document)

    $errors = New-Object System.Collections.Generic.List[string]
    $topRequired = @('schemaVersion', 'runId', 'timestamp', 'profile', 'suite', 'mode',
        'metadata', 'summary', 'cases')
    $topAllowed = @($topRequired) + @('errors')
    [void](Test-SecurityObjectShape $Document $topRequired $topAllowed 'result' $errors)

    if ([int](Get-SecurityDocumentValue $Document 'schemaVersion') -ne 1) {
        $errors.Add('schemaVersion 必须为 1')
    }
    $timestampValue = Get-SecurityDocumentValue $Document 'timestamp'
    $timestamp = if ($timestampValue -is [datetime]) {
        ([datetime]$timestampValue).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    }
    else {
        [string]$timestampValue
    }
    if ($timestamp -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') {
        $errors.Add("timestamp 格式非法: $timestamp")
    }
    if (@('dev', 'standard', 'release', 'baseline') -notcontains [string](Get-SecurityDocumentValue $Document 'profile')) {
        $errors.Add('profile 非法')
    }

    $metadata = Get-SecurityDocumentValue $Document 'metadata'
    $metaRequired = @('gitCommit', 'gitDirty', 'osBuild', 'powershell', 'dllSha256',
        'workerSha256', 'serviceSha256', 'registrySha256')
    [void](Test-SecurityObjectShape $metadata $metaRequired $metaRequired 'metadata' $errors)
    $registryHash = [string](Get-SecurityDocumentValue $metadata 'registrySha256')
    if ($registryHash -notmatch '^[0-9a-f]{64}$') {
        $errors.Add('metadata.registrySha256 必须为 64 位小写十六进制')
    }

    $summary = Get-SecurityDocumentValue $Document 'summary'
    $summaryRequired = @('total', 'pass', 'fail', 'skip', 'blocked', 'error', 'notRun',
        'requiredFailures', 'behavioral', 'static', 'evidence', 'control')
    [void](Test-SecurityObjectShape $summary $summaryRequired $summaryRequired 'summary' $errors)
    foreach ($name in $summaryRequired) {
        $value = Get-SecurityDocumentValue $summary $name
        if (-not ($value -is [int] -or $value -is [long]) -or [int64]$value -lt 0) {
            $errors.Add("summary.$name 必须为非负整数")
        }
    }

    $cases = Get-SecurityDocumentValue $Document 'cases'
    if (-not ($cases -is [System.Array])) {
        $errors.Add('cases 必须为数组')
    }
    else {
        $caseRequired = @('id', 'legacyId', 'name', 'suite', 'severity', 'requirement',
            'kind', 'status', 'expected', 'observed', 'evidence', 'durationMs', 'executorExit')
        $caseAllowed = $caseRequired
        $caseIds = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::Ordinal)
        foreach ($case in $cases) {
            [void](Test-SecurityObjectShape $case $caseRequired $caseAllowed 'case' $errors)
            $id = [string](Get-SecurityDocumentValue $case 'id')
            if ([string]::IsNullOrWhiteSpace($id)) {
                $errors.Add('case.id 不能为空')
            }
            elseif (-not $caseIds.Add($id)) {
                $errors.Add("case.id 重复: $id")
            }
            if (@('vault', 'service', 'tpm') -notcontains [string](Get-SecurityDocumentValue $case 'suite')) {
                $errors.Add("case $id suite 非法")
            }
            if (@('behavioral', 'static', 'evidence', 'control') -notcontains [string](Get-SecurityDocumentValue $case 'kind')) {
                $errors.Add("case $id kind 非法")
            }
            if (@('PASS', 'FAIL', 'SKIP', 'BLOCKED', 'ERROR', 'NOT_RUN') -notcontains [string](Get-SecurityDocumentValue $case 'status')) {
                $errors.Add("case $id status 非法")
            }
            $caseExpected = [string](Get-SecurityDocumentValue $case 'expected')
            $caseObserved = [string](Get-SecurityDocumentValue $case 'observed')
            if ([string]::IsNullOrWhiteSpace($caseExpected) -or [string]::IsNullOrWhiteSpace($caseObserved)) {
                $errors.Add("case $id 必须同时提供 expected 与 observed")
            }
            $duration = Get-SecurityDocumentValue $case 'durationMs'
            if (-not ($duration -is [int] -or $duration -is [long]) -or [int64]$duration -lt 0) {
                $errors.Add("case $id durationMs 必须为非负整数")
            }
        }
    }

    return [pscustomobject]@{
        Valid  = ($errors.Count -eq 0)
        Errors = @($errors)
    }
}

function ConvertTo-SecurityJUnit {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context)

    $rows = @(Get-SecurityCaseRows -Context $Context)
    $summary = Get-SecuritySummary -Context $Context
    $settings = New-Object System.Xml.XmlWriterSettings
    $settings.Indent = $true
    $settings.Encoding = New-Object System.Text.UTF8Encoding($false)
    $settings.OmitXmlDeclaration = $true
    $builder = New-Object System.Text.StringBuilder
    $writer = [System.Xml.XmlWriter]::Create($builder, $settings)

    try {
        $writer.WriteStartElement('testsuites')
        $writer.WriteAttributeString('name', 'verthys-security')
        $writer.WriteAttributeString('tests', [string]$rows.Count)
        $writer.WriteAttributeString('failures', [string]($summary.fail))
        $writer.WriteAttributeString('errors', [string]($summary.error))
        $writer.WriteAttributeString('skipped', [string]($summary.skip + $summary.blocked + $summary.notRun))

        foreach ($suite in @('vault', 'service', 'tpm')) {
            $suiteRows = @($rows | Where-Object { $_.suite -eq $suite })
            if ($suiteRows.Count -eq 0) { continue }
            $suiteFail = @($suiteRows | Where-Object { $_.status -eq 'FAIL' }).Count
            $suiteError = @($suiteRows | Where-Object { $_.status -eq 'ERROR' }).Count
            $suiteSkip = @($suiteRows | Where-Object { $_.status -in @('SKIP', 'BLOCKED', 'NOT_RUN') }).Count
            $writer.WriteStartElement('testsuite')
            $writer.WriteAttributeString('name', $suite)
            $writer.WriteAttributeString('tests', [string]$suiteRows.Count)
            $writer.WriteAttributeString('failures', [string]$suiteFail)
            $writer.WriteAttributeString('errors', [string]$suiteError)
            $writer.WriteAttributeString('skipped', [string]$suiteSkip)

            foreach ($row in $suiteRows) {
                $writer.WriteStartElement('testcase')
                $writer.WriteAttributeString('classname', $row.suite)
                $writer.WriteAttributeString('name', ('{0} {1}' -f $row.id, $row.name))
                $seconds = [Math]::Round(([double]$row.durationMs) / 1000.0, 3)
                $writer.WriteAttributeString('time', $seconds.ToString([Globalization.CultureInfo]::InvariantCulture))
                $message = 'expected={0}; observed={1}' -f $row.expected, $row.observed

                switch ($row.status) {
                    'FAIL' {
                        $writer.WriteStartElement('failure')
                        $writer.WriteAttributeString('message', $message)
                        $writer.WriteString($message)
                        $writer.WriteEndElement()
                    }
                    'ERROR' {
                        $writer.WriteStartElement('error')
                        $writer.WriteAttributeString('message', $message)
                        $writer.WriteString($message)
                        $writer.WriteEndElement()
                    }
                    { $_ -in @('SKIP', 'BLOCKED', 'NOT_RUN') } {
                        $writer.WriteStartElement('skipped')
                        $writer.WriteAttributeString('message', ('{0}: {1}' -f $row.status, $message))
                        $writer.WriteEndElement()
                    }
                }
                $writer.WriteEndElement()
            }
            $writer.WriteEndElement()
        }

        $writer.WriteEndElement()
    }
    finally {
        $writer.Dispose()
    }
    $declaration = '<?xml version="1.0" encoding="utf-8"?>'
    return ($declaration + [Environment]::NewLine + $builder.ToString())
}

function ConvertTo-SecuritySarif {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context)

    $rows = @(Get-SecurityCaseRows -Context $Context)
    $rules = New-Object System.Collections.Generic.List[object]
    $results = New-Object System.Collections.Generic.List[object]
    foreach ($row in $rows) {
        $message = 'expected={0}; observed={1}' -f $row.expected, $row.observed
        $rules.Add([ordered]@{
                id               = [string]$row.id
                name             = [string]$row.name
                shortDescription = [ordered]@{ text = [string]$row.name }
                properties       = [ordered]@{
                    legacyId    = [string]$row.legacyId
                    suite       = [string]$row.suite
                    kind        = [string]$row.kind
                    severity    = [string]$row.severity
                    requirement = [string]$row.requirement
                }
            })

        if ($row.status -eq 'PASS') { continue }
        $level = switch ($row.status) {
            'FAIL' { 'error' }
            'ERROR' { 'error' }
            'BLOCKED' { 'warning' }
            default { 'note' }
        }
        $results.Add([ordered]@{
                ruleId     = [string]$row.id
                level      = $level
                message    = [ordered]@{ text = ('[{0}] {1}' -f $row.status, $message) }
                properties = [ordered]@{
                    status   = [string]$row.status
                    legacyId = [string]$row.legacyId
                    suite    = [string]$row.suite
                    evidence = $(if ([string]::IsNullOrWhiteSpace([string]$row.evidence)) { $null } else { [string]$row.evidence })
                }
            })
    }

    $document = [ordered]@{
        '$schema' = 'https://json.schemastore.org/sarif-2.1.0.json'
        version   = '2.1.0'
        runs      = @(
            [ordered]@{
                tool    = [ordered]@{
                    driver = [ordered]@{
                        name            = 'Verthys Security Suite'
                        informationUri = 'https://verthys.local/security-testing'
                        rules           = $rules.ToArray()
                    }
                }
                results = $results.ToArray()
            }
        )
    }
    return $document
}

function ConvertTo-SecurityMarkdown {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context)

    $summary = Get-SecuritySummary -Context $Context
    $rows = @(Get-SecurityCaseRows -Context $Context)
    $metadata = $Context.Metadata
    $lines = New-Object System.Collections.Generic.List[string]

    $lines.Add('# Verthys 安全测试报告')
    $lines.Add('')
    $lines.Add('| 项目 | 值 |')
    $lines.Add('| --- | --- |')
    $lines.Add(('| Run ID | `{0}` |' -f $Context.RunId))
    $lines.Add(('| Profile | `{0}` |' -f $Context.Profile))
    $lines.Add(('| Suite | `{0}` |' -f $Context.Suite))
    $lines.Add(('| Mode | `{0}` |' -f $Context.Mode))
    $lines.Add(('| 时间 | `{0}` |' -f $Context.Timestamp))
    $lines.Add(('| Git | `{0}`{1} |' -f $metadata.gitCommit, $(if ($metadata.gitDirty) { ' (dirty)' } else { '' })))
    $lines.Add(('| DLL SHA-256 | `{0}` |' -f $(if ($metadata.dllSha256) { $metadata.dllSha256 } else { '未构建' })))
    $lines.Add(('| Worker SHA-256 | `{0}` |' -f $(if ($metadata.workerSha256) { $metadata.workerSha256 } else { '未构建' })))
    $lines.Add(('| Service SHA-256 | `{0}` |' -f $(if ($metadata.serviceSha256) { $metadata.serviceSha256 } else { '未构建' })))
    $lines.Add(('| Registry SHA-256 | `{0}` |' -f $metadata.registrySha256))
    $lines.Add('')
    $lines.Add(('汇总：PASS {0} · FAIL {1} · SKIP {2} · BLOCKED {3} · ERROR {4} · NOT_RUN {5} · 必需项未通过 {6}' -f
            $summary.pass, $summary.fail, $summary.skip, $summary.blocked, $summary.error,
            $summary.notRun, $summary.requiredFailures))
    $lines.Add(('用例构成：behavioral {0} · static {1} · evidence {2} · control {3}' -f
            $summary.behavioral, $summary.static, $summary.evidence, $summary.control))
    $lines.Add('')

    foreach ($suite in @('vault', 'service', 'tpm')) {
        $suiteRows = @($rows | Where-Object { $_.suite -eq $suite })
        if ($suiteRows.Count -eq 0) { continue }
        $lines.Add(('## {0}' -f $suite))
        $lines.Add('')
        $lines.Add('| 用例 | Legacy | 状态 | 期望 | 观测 | 证据 |')
        $lines.Add('| --- | --- | --- | --- | --- | --- |')
        foreach ($row in $suiteRows) {
            $expected = ([string]$row.expected).Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ')
            $observed = ([string]$row.observed).Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ')
            $evidence = if ([string]::IsNullOrWhiteSpace([string]$row.evidence)) { '' } else { ([string]$row.evidence).Replace('|', '\|') }
            $lines.Add(('| {0} {1} | {2} | **{3}** | {4} | {5} | {6} |' -f
                    $row.id, $row.name, $row.legacyId, $row.status, $expected, $observed, $evidence))
        }
        $lines.Add('')
    }

    if ($Context.Errors.Count -gt 0) {
        $lines.Add('## 执行错误')
        $lines.Add('')
        foreach ($message in $Context.Errors) { $lines.Add(('- {0}' -f $message)) }
        $lines.Add('')
    }

    return ($lines -join [Environment]::NewLine)
}

function Write-SecurityAtomicFile {
    param([string]$Path, [string]$Content)
    $parent = Split-Path -Parent $Path
    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item -ItemType Directory -Path $parent -Force | Out-Null
    }
    $temp = '{0}.tmp-{1}' -f $Path, [guid]::NewGuid().ToString('N')
    try {
        [System.IO.File]::WriteAllText($temp, $Content, (New-Object System.Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temp -Destination $Path -Force
    }
    finally {
        if (Test-Path -LiteralPath $temp) {
            Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-SecurityArtifacts {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)]$Context)

    if (-not (Test-Path -LiteralPath $Context.OutDir)) {
        New-Item -ItemType Directory -Path $Context.OutDir -Force | Out-Null
    }

    $document = Get-SecurityResultDocument -Context $Context
    $validation = Test-SecurityResultDocument -Document $document
    if (-not $validation.Valid) {
        $Context.Errors.Add('结果不符合 schema：' + ($validation.Errors -join '; '))
        $document = Get-SecurityResultDocument -Context $Context
    }

    $jsonPath = Join-Path $Context.OutDir 'result.json'
    $junitPath = Join-Path $Context.OutDir 'result.junit.xml'
    $sarifPath = Join-Path $Context.OutDir 'result.sarif'
    $markdownPath = Join-Path $Context.OutDir 'summary.md'

    Write-SecurityAtomicFile -Path $jsonPath -Content ($document | ConvertTo-Json -Depth 12)
    Write-SecurityAtomicFile -Path $junitPath -Content (ConvertTo-SecurityJUnit -Context $Context)
    Write-SecurityAtomicFile -Path $sarifPath -Content ((ConvertTo-SecuritySarif -Context $Context) | ConvertTo-Json -Depth 12)
    Write-SecurityAtomicFile -Path $markdownPath -Content (ConvertTo-SecurityMarkdown -Context $Context)

    return [pscustomobject]@{
        Json     = $jsonPath
        JUnit    = $junitPath
        Sarif    = $sarifPath
        Markdown = $markdownPath
        Valid    = $validation.Valid
    }
}

Export-ModuleMember -Function New-SecurityRunContext, Add-SecurityCaseResult,
ConvertTo-SecurityStatus, Get-SecurityCaseRows, Get-SecuritySummary, Get-SecurityExitCode,
Get-SecurityResultDocument, Test-SecurityResultDocument, ConvertTo-SecurityJUnit,
ConvertTo-SecuritySarif, ConvertTo-SecurityMarkdown, Write-SecurityArtifacts
