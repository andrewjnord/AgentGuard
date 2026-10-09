<#
.SYNOPSIS
  Builds the dashboard and publishes every AgentGuard binary (self-contained, win-x64) into one folder, ready for the MSI.

.EXAMPLE
  ./build/publish.ps1 -Version 0.1.42 -Output artifacts/app
#>
param(
    [string]$Version = "0.1.0",
    [string]$Output = "artifacts/app",
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

if (Test-Path $Output) { Remove-Item $Output -Recurse -Force }
New-Item -ItemType Directory -Force $Output | Out-Null

Write-Host "== Dashboard"
Push-Location src/dashboard
npm ci --no-audit --no-fund
if ($LASTEXITCODE -ne 0) { throw "npm ci failed" }
npm run build
if ($LASTEXITCODE -ne 0) { throw "dashboard build failed" }
Pop-Location

# All apps share one folder and one .NET runtime version, so overlapping runtime files are identical.
# The tray goes last: it carries the Windows Desktop runtime on top of the base runtime.
$projects = @(
    "src/AgentGuard.Service/AgentGuard.Service.csproj",
    "src/AgentGuard.McpProxy/AgentGuard.McpProxy.csproj",
    "src/AgentGuard.Hook/AgentGuard.Hook.csproj",
    "src/AgentGuard.Cli/AgentGuard.Cli.csproj",
    "src/AgentGuard.Tray/AgentGuard.Tray.csproj"
)
foreach ($p in $projects) {
    Write-Host "== $p"
    dotnet publish $p -c $Configuration -r $Runtime --self-contained true -o $Output `
        -p:Version=$Version -p:DebugType=none -p:GenerateDocumentationFile=false
    if ($LASTEXITCODE -ne 0) { throw "publish failed: $p" }
}

foreach ($required in @("AgentGuard.Service.exe", "agentguard-mcp-proxy.exe", "agentguard-hook.exe", "agentguard.exe", "AgentGuard.Tray.exe", "wwwroot/index.html", "defaults/policies/default.yaml", "defaults/signatures/agents.yaml")) {
    if (-not (Test-Path (Join-Path $Output $required))) { throw "Missing from the published app: $required" }
}
Write-Host "Published AgentGuard $Version to $Output"
