param([string]$Executable = "$PSScriptRoot/../build-release/modern-standby-auditor.exe")
$ErrorActionPreference = 'Stop'
$jsonText = & $Executable --json
if ($LASTEXITCODE -ne 0) { throw 'JSON audit failed' }
$report = $jsonText | ConvertFrom-Json
$schemaPath = Join-Path $PSScriptRoot '../schema.json'
if (-not ($jsonText | Test-Json -SchemaFile $schemaPath)) { throw 'JSON schema validation failed' }
foreach ($section in 'system_context','capabilities','current_snapshot','wake_metadata','historical_evidence','limitations') {
    $names = @($report.$section | ForEach-Object name)
    if (@($names | Select-Object -Unique).Count -ne $names.Count) { throw "Duplicate field in $section" }
}
$capability = @($report.capabilities | Where-Object name -eq 's0_low_power_idle')
if ($capability.Count -ne 1) { throw 'Missing Modern Standby result' }
$history = @($report.historical_evidence | Where-Object name -eq 'sleep_wake_history')
if ($history.Count -ne 1 -or $history[0].status -ne 'unavailable' -or $null -ne $history[0].value) { throw 'History must be explicit and unavailable' }
Write-Output 'Live JSON schema and semantic validation passed'
