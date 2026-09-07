$ErrorActionPreference = "Stop"

$taskName = "BlogPublishQueueAlert"
$scriptPath = Join-Path $PSScriptRoot "check-publish-queue.ps1"
$workDir = Split-Path -Parent $PSScriptRoot

if (-not (Test-Path -LiteralPath $scriptPath)) {
  throw "Queue checker not found: $scriptPath"
}

$action = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Target dev" `
  -WorkingDirectory $workDir

$trigger = New-ScheduledTaskTrigger `
  -Weekly `
  -DaysOfWeek Monday,Tuesday,Wednesday,Thursday,Friday `
  -At (Get-Date -Date "10:00")

$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

Register-ScheduledTask `
  -TaskName $taskName `
  -Action $action `
  -Trigger $trigger `
  -Settings $settings `
  -Description "Weekday 10:00 alert when the dev Blogger Markdown publish queue is empty." `
  -Force | Out-Null

Write-Output "Registered task '$taskName' (Monday-Friday at 10:00)."
