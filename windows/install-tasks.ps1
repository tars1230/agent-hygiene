# Registers / removes the two scheduled tasks for agent-hygiene.
# Run from an elevated PowerShell 5.1+ window.
#
#   .\install-tasks.ps1 -ScriptDir "C:\agent-hygiene\tools" -Python "C:\path\to\python.exe"
#   .\install-tasks.ps1 -Remove
#
# Tasks:
#   CodexSandbox-Cleanup : daily 05:00 + at-logon(delay 15min), elevated  -> reclaim script
#   AgentHygiene-Weekly  : Mondays 05:10, non-elevated                   -> read-only audit

param(
    [string]$Python = "python",
    [string]$ScriptDir = "",
    [switch]$Remove
)

$ErrorActionPreference = "Stop"

if ($Remove) {
    foreach ($n in @("CodexSandbox-Cleanup", "AgentHygiene-Weekly")) {
        if (Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $n -Confirm:$false
            Write-Host "removed task: $n"
        } else {
            Write-Host "not found, skipped: $n"
        }
    }
    exit 0
}

if (-not $ScriptDir) {
    # default: assume this script lives in <repo>\windows, tools are at <repo>\tools
    $ScriptDir = Join-Path (Split-Path -Parent $PSScriptRoot) "tools"
}
$audit  = Join-Path $ScriptDir "agent_hygiene_audit.py"
$clean  = Join-Path $ScriptDir "codex_sandbox_cleanup.py"
foreach ($f in @($audit, $clean)) {
    if (-not (Test-Path $f)) { throw "script not found: $f" }
}
$userId = "$env:USERDOMAIN\$env:USERNAME"

# --- CodexSandbox-Cleanup (needs elevation: stops/starts a service) ---
$act = New-ScheduledTaskAction -Execute $Python -Argument ('"' + $clean + '" --apply')
$t1  = New-ScheduledTaskTrigger -AtLogOn
$t1.Delay = "PT15M"
$t2  = New-ScheduledTaskTrigger -Daily -At 05:00
$set = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 5) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$pr  = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Highest
Register-ScheduledTask -TaskName "CodexSandbox-Cleanup" -Action $act -Trigger @($t1, $t2) -Settings $set -Principal $pr -Force | Out-Null
Write-Host "registered: CodexSandbox-Cleanup (daily 05:00 + logon+15min, Highest)"

# --- AgentHygiene-Weekly (read-only, no elevation needed) ---
$act2 = New-ScheduledTaskAction -Execute $Python -Argument ('"' + $audit + '" --top 15')
$t3   = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 05:10
$set2 = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
$pr2  = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited
Register-ScheduledTask -TaskName "AgentHygiene-Weekly" -Action $act2 -Trigger $t3 -Settings $set2 -Principal $pr2 -Force | Out-Null
Write-Host "registered: AgentHygiene-Weekly (Mondays 05:10, Limited)"

Write-Host ""
Write-Host "Reports:  %LOCALAPPDATA%\agent-hygiene\reports"
Write-Host "Logs:     %LOCALAPPDATA%\agent-hygiene\logs"
Write-Host "Remove:   .\install-tasks.ps1 -Remove"
