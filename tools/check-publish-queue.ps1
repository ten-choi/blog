param(
  [string]$Target = "dev"
)

$ErrorActionPreference = "Stop"
$repoRoot = Split-Path -Parent $PSScriptRoot
$queuePath = Join-Path $repoRoot "content\$Target"
$logPath = Join-Path $repoRoot "tools\queue-check-$Target.log"

if (-not (Test-Path -LiteralPath $queuePath)) {
  throw "Queue directory not found: $queuePath"
}

$drafts = Get-ChildItem -LiteralPath $queuePath -Recurse -Filter "*.md" -File |
  Where-Object { $_.FullName -notmatch "\\drafts\\" } |
  Where-Object {
    $content = Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8
    $content -match '(?m)^published:\s*false\s*$'
  } |
  Sort-Object FullName

$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
if ($drafts.Count -gt 0) {
  Add-Content -LiteralPath $logPath -Value "[$timestamp][$Target] Queue has $($drafts.Count) unpublished post(s)." -Encoding UTF8
  exit 0
}

$message = "Blog publish queue is empty ($Target). No unpublished Markdown post is waiting."
Add-Content -LiteralPath $logPath -Value "[$timestamp][$Target] $message" -Encoding UTF8
try {
  & "$env:WINDIR\System32\msg.exe" * $message 2>$null
} catch {
  Add-Content -LiteralPath $logPath -Value "[$timestamp][$Target] Windows alert failed: $($_.Exception.Message)" -Encoding UTF8
}
