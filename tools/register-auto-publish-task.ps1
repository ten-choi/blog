# Register a Windows Task Scheduler entry that runs auto-publish-next.ps1 for the
# given target, on a WEEKLY Mon-Fri schedule, TWICE per day (2 posts/day per blog;
# 4 posts/day total across dev + language).
#
# Hard constraints:
#   - Weekdays only (Mon-Fri), every week.
#   - Every publish lands inside 10:00-17:00 (the user is at the PC then; the task
#     only runs while logged on, so it must stay in this window).
#   - dev and language are interleaved across the day so they never collide and the
#     4 posts are spread out (bursty same-time posting looks automated / low-quality):
#
#   order  target     base + jitter (PT30M)
#     1    dev        10:00 + 0-30m  -> 10:00-10:30
#     2    language   11:45 + 0-30m  -> 11:45-12:15
#     3    dev        13:45 + 0-30m  -> 13:45-14:15
#     4    language   15:45 + 0-30m  -> 15:45-16:15
#
# Each trigger fires the worker once -> one post. The random delay is recomputed by
# Task Scheduler on every occurrence, so the exact minute differs each day.
#
# StartWhenAvailable is intentionally OFF: if the PC is off at a trigger time the
# slot is skipped rather than running later outside 10:00-17:00.
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

$taskName   = "BlogAutoPublish-$Target"
$scriptPath = "C:\workSpace\projects\personal\blog\tools\auto-publish-next.ps1"
$workDir    = "C:\workSpace\projects\personal\blog"

if (-not (Test-Path $scriptPath)) {
  throw "Worker script not found at $scriptPath"
}

# Anchor the time-of-day on tomorrow's date so nothing fires today; the weekly
# Mon-Fri recurrence takes over from there.
$startDate = (Get-Date).Date.AddDays(1)
if ($Target -eq "dev") {
  $slot1 = $startDate.AddHours(10)                 # 10:00 -> 10:00-10:30
  $slot2 = $startDate.AddHours(13).AddMinutes(45)  # 13:45 -> 13:45-14:15
} else {  # language
  $slot1 = $startDate.AddHours(11).AddMinutes(45)  # 11:45 -> 11:45-12:15
  $slot2 = $startDate.AddHours(15).AddMinutes(45)  # 15:45 -> 15:45-16:15
}
$jitter = "PT30M"  # ISO 8601: up to 30 minutes of random delay
$weekdays = @('Monday','Tuesday','Wednesday','Thursday','Friday')

$action = New-ScheduledTaskAction `
  -Execute "powershell.exe" `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Target $Target" `
  -WorkingDirectory $workDir

$trigger1 = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $weekdays -At $slot1
$trigger1.RandomDelay = $jitter

$trigger2 = New-ScheduledTaskTrigger -Weekly -DaysOfWeek $weekdays -At $slot2
$trigger2.RandomDelay = $jitter

# No -StartWhenAvailable: keep every run strictly inside the 10:00-17:00 window.
$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -ExecutionTimeLimit (New-TimeSpan -Hours 1)

Register-ScheduledTask `
  -TaskName $taskName `
  -Action $action `
  -Trigger $trigger1, $trigger2 `
  -Settings $settings `
  -Description "Weekday (Mon-Fri) blog auto-publish for $Target, 2 posts/day. Slots $($slot1.ToString('HH:mm')) +0-30m and $($slot2.ToString('HH:mm')) +0-30m; interleaved with the other blog and kept inside 10:00-17:00. Logs: tools\auto-publish-$Target.log." `
  -Force | Out-Null

Write-Output "Registered task '$taskName' (Mon-Fri, 2 runs/day)."
Write-Output ("  Slot 1: Mon-Fri {0} + random 0-30m" -f $slot1.ToString('HH:mm'))
Write-Output ("  Slot 2: Mon-Fri {0} + random 0-30m" -f $slot2.ToString('HH:mm'))
Write-Output "  Window : all runs inside 10:00-17:00 (StartWhenAvailable OFF)"
Write-Output "  Action : powershell.exe -File $scriptPath -Target $Target"
Write-Output "  Logs   : C:\workSpace\projects\personal\blog\tools\auto-publish-$Target.log"
