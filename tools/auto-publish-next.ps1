# Auto-publish one post per scheduled run for the given blog target.
# Picks the alphabetically-first eligible draft under blogs/<target>/,
# flips frontmatter published: false -> true, runs publish.ts, then commits locally.
# Does NOT push — user pushes manually after reviewing the commit.
#
# Randomization is handled by Task Scheduler's RandomDelay (set in register-auto-publish-task.ps1),
# so this script runs immediately when invoked. For manual testing, invoke directly:
#   .\auto-publish-next.ps1 -Target language

param(
  [Parameter(Mandatory = $true)][ValidateSet("dev","language")][string]$Target
)

$ErrorActionPreference = "Stop"
$repoRoot = "C:\workSpace\projects\personal\blog"
$logFile  = Join-Path $repoRoot "tools\auto-publish-$Target.log"

$blogIds = @{
  "dev"      = "3666962477256387094"
  "language" = "6585438201171100645"
}
$blogId = $blogIds[$Target]

function Log($msg) {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "[$ts][$Target] $msg"
  Add-Content -Path $logFile -Value $line -Encoding UTF8
  Write-Output $line
}

Set-Location $repoRoot

# Find candidate drafts under blogs/<target>/ (exclude drafts/ staging folder).
$candidates = Get-ChildItem -Path "blogs\$Target" -Recurse -Filter "*.md" -File |
  Where-Object { $_.FullName -notmatch "\\drafts\\" } |
  Sort-Object FullName

$next  = $null
$title = $null
foreach ($file in $candidates) {
  $content = Get-Content -Path $file.FullName -Raw -Encoding UTF8
  if ($content -notmatch '(?m)^published:\s*false\s*$') { continue }
  if ($content -match '(?m)^title:\s*"?([^"\r\n]*?)"?\s*$') {
    $candidateTitle = $matches[1].Trim()
    if ($candidateTitle) {
      $next  = $file
      $title = $candidateTitle
      break
    }
  }
}

if (-not $next) {
  Log "No eligible drafts. Queue empty."
  exit 0
}

Log "Selected: $($next.FullName) (title: $title)"

# Flip published: false -> true, preserving original encoding (UTF-8, no BOM).
$original  = Get-Content -Path $next.FullName -Raw -Encoding UTF8
$updated   = $original -replace '(?m)^published:\s*false\s*$', 'published: true'
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($next.FullName, $updated, $utf8NoBom)

$prevEAP        = $ErrorActionPreference
$bloggerUpdated = $false
try {
  # PS 5.1 wraps native-cmd stderr lines as NativeCommandError when merged via 2>&1;
  # with EAP=Stop, harmless warnings (npm notice, git CRLF warning) become terminating
  # errors. Switch to Continue here and rely on the explicit $LASTEXITCODE checks.
  $ErrorActionPreference = "Continue"
  $env:BLOGGER_BLOG_ID = $blogId

  $output = & npm run publish:blogger -- "$($next.FullName)" 2>&1 | Out-String
  Log "publish.ts output:`n$output"
  if ($LASTEXITCODE -ne 0) { throw "publish.ts exited with code $LASTEXITCODE" }
  $bloggerUpdated = $true

  & git add -- "$($next.FullName)" 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "git add failed" }

  # Pathspec-scoped commit so unrelated pre-staged changes in the index don't get
  # swept into the auto-publish commit.
  & git commit -m "publish($Target): $title" -- "$($next.FullName)" 2>&1 | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "git commit failed" }

  Log "SUCCESS: $title (committed locally; push manually when ready)"
} catch {
  if ($bloggerUpdated) {
    # Blogger already has the new content; reverting frontmatter would cause the
    # next run to re-publish the same file. Leave the file as published: true and
    # let the user reconcile manually.
    Log "FAILED after Blogger update: $($_.Exception.Message). Frontmatter left as published: true on $($next.FullName); reconcile/commit manually."
  } else {
    # Blogger publish never succeeded — revert frontmatter so the file stays in the queue.
    [System.IO.File]::WriteAllText($next.FullName, $original, $utf8NoBom)
    Log "FAILED before Blogger update: $($_.Exception.Message); reverted frontmatter on $($next.FullName)"
  }
  exit 1
} finally {
  $ErrorActionPreference = $prevEAP
}
