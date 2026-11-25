#!/bin/bash
# Publish uploaded Blogger drafts one by one, oldest first, with a random
# 7-15 minute gap, optionally at most MAX_PER_DAY per day (env, default 0 = no cap). When the day's cap is
# reached it waits until 09:00-09:30 the next day and continues.
#
# Picks files under content/dev/YYYY-H1|H2 with `published: false` and a
# bloggerPostId, sorted by front-matter date. For each it flips the front matter
# to `published: true`, runs publish.ts (posts.update with publish=true keeps the
# original date) and commits the file. On a quota error the file is flipped back
# and the run stops; re-run later to continue. Posts with relative image links
# (images that never made it to the CDN) are skipped.
#
# Log: tools/publish-drafts.log
# Usage (Git Bash):  bash tools/publish-drafts.sh
cd "$(dirname "$0")/.." || exit 1
L="tools/publish-drafts.log"
MAX_PER_DAY=${MAX_PER_DAY:-0}  # 0 = no daily cap
# A fresh shell may not have fnm's node on PATH.
command -v npx >/dev/null || PATH="$APPDATA/fnm/aliases/default:$PATH"
command -v npx >/dev/null || { echo "ABORT $(date '+%F %T') npx not found" >> "$L"; exit 1; }
QUEUE=$(mktemp)
for f in content/dev/20[0-9][0-9]-H[12]/*.md; do
  grep -qE '^published:\s*false' "$f" || continue
  grep -qE '^bloggerPostId:\s*"?[0-9]' "$f" || continue
  if grep -qE '\]\((\./)?images/' "$f"; then echo "SKIP (local images) $(basename "$f")" >> "$L"; continue; fi
  d=$(grep -m1 -E '^date:' "$f" | sed 's/^date:\s*//; s/"//g')
  printf '%s\t%s\n' "$(date -d "$d" +%s)" "$f"
done | sort -n | cut -f2- > "$QUEUE"
total=$(wc -l < "$QUEUE"); n=0; fails=0
echo "START queue=$total $(date '+%F %T')" >> "$L"
while IFS= read -r f; do
  [ -z "$f" ] && continue
  if [ "$MAX_PER_DAY" -gt 0 ] && [ "$(grep -c "^LIVE .* $(date +%F) " "$L")" -ge $MAX_PER_DAY ]; then
    wake=$(( $(date -d "tomorrow 09:00" +%s) + RANDOM % 1801 ))
    echo "CAP $(date '+%F %T') $MAX_PER_DAY published today, next at $(date -d "@$wake" '+%F %T')" >> "$L"
    sleep $(( wake - $(date +%s) ))
  else
    # gap counts from the last publish, also across re-runs
    last=$(grep '^LIVE ' "$L" | tail -1 | awk '{print $3" "$4}')
    if [ -n "$last" ]; then
      left=$(( $(date -d "$last" +%s) + 420 + RANDOM % 481 - $(date +%s) ))
      [ $left -gt 0 ] && sleep $left
    fi
  fi
  sed -i 's/^published:\s*false/published: true/' "$f"
  out=$(npx ts-node platforms/blogger/publish.ts "$f" 2>&1)
  if echo "$out" | grep -q "UPDATED"; then
    n=$((n+1))
    title=$(grep -m1 -E '^title:' "$f" | sed 's/^title:\s*//; s/^"//; s/"\s*$//')
    git add -- "$f" && git commit -q -m "publish(dev): $title" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>" -- "$f"
    echo "LIVE [$n/$total] $(date '+%F %T') $(basename "$f")" >> "$L"
  elif echo "$out" | grep -qiE "exhausted|rateLimitExceeded|quota"; then
    sed -i 's/^published:\s*true/published: false/' "$f"
    echo "STOP $(date '+%F %T') quota hit at $(basename "$f")" >> "$L"
    break
  else
    sed -i 's/^published:\s*true/published: false/' "$f"
    echo "FAIL $(basename "$f"): $(echo "$out" | grep -iE 'fatal|error' | head -1 | cut -c1-150)" >> "$L"
    fails=$((fails+1))
    # repeated failures mean the environment is broken, not the post
    [ $fails -ge 3 ] && { echo "ABORT $(date '+%F %T') 3 failures in a row" >> "$L"; break; }
    continue
  fi
  fails=0
done < "$QUEUE"
rm -f "$QUEUE"
echo "END published=$n $(date '+%F %T')" >> "$L"
tail -3 "$L"
