<#
.SYNOPSIS
  Installs the MSI on a clean Windows machine (the CI runner), checks that every part comes up, then uninstalls it
  and checks that nothing is left behind except the data folder. Needs an elevated session.
#>
param([Parameter(Mandatory)] [string]$Msi)
$ErrorActionPreference = "Stop"
$logs = Join-Path (Get-Location) "artifacts/logs"
New-Item -ItemType Directory -Force $logs | Out-Null
$installDir = Join-Path $env:ProgramFiles "AgentGuard"
$hookFile = Join-Path $env:ProgramFiles "ClaudeCode\managed-settings.d\agentguard.json"
function Check($ok, $what) { if (-not $ok) { throw "SMOKE TEST FAILED: $what" } ; Write-Host "ok  $what" }
# A CI runner is not a real interactive desktop: report tray problems as warnings for a person to look at.
function Soft($ok, $what) { if ($ok) { Write-Host "ok  $what" } else { Write-Host "::warning::Tray check failed on the CI runner: $what (verify on a real desktop)" } }

Write-Host "== Install"
$p = Start-Process msiexec.exe -ArgumentList "/i `"$Msi`" /qn /norestart /l*v `"$logs\install.log`"" -Wait -PassThru
Check ($p.ExitCode -eq 0) "msiexec install exit code ($($p.ExitCode))"

$svc = Get-Service AgentGuard -ErrorAction SilentlyContinue
Check ($null -ne $svc) "service registered"
$svc.WaitForStatus("Running", [TimeSpan]::FromSeconds(60))
Check ((Get-Service AgentGuard).Status -eq "Running") "service running"
Check ((Get-CimInstance Win32_Service -Filter "Name='AgentGuard'").StartName -eq "LocalSystem") "service runs as LocalSystem"

$health = $null
for ($i = 0; $i -lt 30 -and -not $health; $i++) {
    try { $health = Invoke-RestMethod http://127.0.0.1:47823/api/v1/health } catch { Start-Sleep 1 }
}
Check ($health.ok -eq $true) "API health"
$page = Invoke-WebRequest http://127.0.0.1:47823/ -UseBasicParsing
Check ($page.Content -match "<div id=`"root`"") "dashboard served"
try { Invoke-RestMethod http://127.0.0.1:47823/api/v1/status | Out-Null; Check $false "status requires a token" }
catch { Check ($_.Exception.Response.StatusCode.value__ -eq 401) "status requires a token" }

$cli = Join-Path $installDir "agentguard.exe"
& $cli status | Tee-Object "$logs\status.txt"
Check ($LASTEXITCODE -eq 0) "admin CLI status (elevated, token from the data folder)"
& $cli verify
Check ($LASTEXITCODE -eq 0) "audit log integrity"
& $cli policy validate (Join-Path $installDir "defaults\policies\default.yaml")
Check ($LASTEXITCODE -eq 0) "default policy validates"

Check (Test-Path $hookFile) "Claude Code managed hook registered"
$hookInput = '{"session_id":"s","cwd":"C:\\","hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"~/.ssh/id_rsa"}}'
$out = $hookInput | & (Join-Path $installDir "agentguard-hook.exe")
Check ($out -match '"permissionDecision":"deny"') "hook denies reading SSH keys"
$out = '{"session_id":"s","cwd":"C:\\","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"dir"}}' | & (Join-Path $installDir "agentguard-hook.exe")
Check ([string]::IsNullOrWhiteSpace($out)) "hook stays silent for an allowed command"

# The tray needs a desktop session; on the runner we can check it starts, stays up, and gets its token from the service.
$tray = Start-Process (Join-Path $installDir "AgentGuard.Tray.exe") -PassThru
Start-Sleep 15
Soft (-not $tray.HasExited) "tray app starts and keeps running"
$events = Invoke-RestMethod "http://127.0.0.1:47823/api/v1/events?limit=200" -Headers @{ "X-AgentGuard-Token" = (Get-Content "$env:ProgramData\AgentGuard\admin.token") }
$events.items | ConvertTo-Json -Depth 6 | Out-File "$logs\events.json"
Stop-Process -Id $tray.Id -Force -ErrorAction SilentlyContinue
Get-WinEvent -LogName Application -MaxEvents 200 -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match "AgentGuard|\.NET Runtime|Application Error" } |
    Format-List TimeCreated, ProviderName, Message | Out-File "$logs\eventlog.txt"
Soft (-not (Select-String -Path "$logs\eventlog.txt" -Pattern "AgentGuard.Tray.exe" -Quiet)) "no tray crash in the event log"

Write-Host "== Uninstall"
$p = Start-Process msiexec.exe -ArgumentList "/x `"$Msi`" /qn /norestart /l*v `"$logs\uninstall.log`"" -Wait -PassThru
Check ($p.ExitCode -eq 0) "msiexec uninstall exit code ($($p.ExitCode))"
Check ($null -eq (Get-Service AgentGuard -ErrorAction SilentlyContinue)) "service removed"
Check (-not (Test-Path (Join-Path $installDir "AgentGuard.Service.exe"))) "program files removed"
Check (-not (Test-Path $hookFile) -or -not (Select-String -Path $hookFile -Pattern "agentguard-hook" -Quiet)) "Claude Code hook removed"
Check (Test-Path "$env:ProgramData\AgentGuard\agentguard.db") "audit data kept"
Write-Host "Smoke test passed."
