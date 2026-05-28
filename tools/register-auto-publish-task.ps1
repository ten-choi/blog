# Register a Windows Task Scheduler entry that runs auto-publish-next.ps1
# daily for the given target. Both targets share the same window:
#   trigger 11:00 + random 0-2h  ->  publish lands in 11:00-13:00 JST
# Each daily fire computes a fresh random offset, so two targets rarely overlap
# in practice (and even if they do, different blogs/different files).
#
# Usage (once per target):
#   powershell -ExecutionPolicy Bypass -File .\tools\register-auto-publish-task.ps1 -Target language
#   powershell -ExecutionPolicy Bypass -File .\tools\register-auto-publish-task.ps1 -Target dev
#
# No admin elevation required (registers as the current user).

param(
  [Parameter(Mandatory = $true)][ValidateSet("dev","language")][string]$Target
)

$ErrorActionPreference = "Stop"

$startTime  = "11:00"
$taskName   = "BlogAutoPublish-$Target"
$scriptPath = "C:\workSpace\projects\personal\blog\tools\auto-publish-next.ps1"
$workDir    = "C:\workSpace\projects\personal\blog"

if (-not (Test-Path $scriptPath)) {
  throw "Worker script not found at $scriptPath"
}

$action = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Target $Target" `
  -WorkingDirectory $workDir

$trigger = New-ScheduledTaskTrigger -Daily -At $startTime
$trigger.RandomDelay = "PT2H"   # ISO 8601: up to 2 hours after the trigger time

$settings = New-ScheduledTaskSettingsSet `
  -StartWhenAvailable `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit (New-TimeSpan -Hours 3)

Register-ScheduledTask `
  -TaskName $taskName `
  -Action $action `
  -Trigger $trigger `
  -Settings $settings `
  -Description "Daily blog auto-publish for $Target ($startTime + random 0-2h, fires 11:00-13:00 JST). Logs: tools\auto-publish-$Target.log." `
  -Force | Out-Null

Write-Output "Registered task '$taskName'."
Write-Output "  Trigger: Daily $startTime + random 0-2h delay (fires 11:00-13:00 JST)"
Write-Output "  Action : powershell.exe -File $scriptPath -Target $Target"
Write-Output "  Logs   : C:\workSpace\projects\personal\blog\tools\auto-publish-$Target.log"
