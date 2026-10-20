#!/bin/bash
# Resumable Blogger draft uploader for migrated posts.
#
# Every file under content/dev whose front matter has an empty bloggerPostId and a
# migration source (tistory / archive / blogger) is inserted into Blogger as a DRAFT
# with the date from its front matter. On "Resource has been exhausted" (API quota)
# it waits 10 minutes and retries the same file, so it can simply be re-run until
# everything is up. Progress is appended to tools/upload-drafts.log.
#
# Usage (Git Bash):  bash tools/upload-drafts.sh
cd "$(dirname "$0")/.." || exit 1
L="tools/upload-drafts.log"
PENDING=$(mktemp)
grep -lE '^bloggerPostId:\s*$' content/dev/*/*.md | xargs -d '\n' grep -lE '^source: "(tistory|archive|blogger)"' | sort > "$PENDING"
total=$(wc -l < "$PENDING"); ok=0; fail=0
echo "START pending=$total $(date '+%F %T')" >> "$L"
while IFS= read -r f; do
  [ -z "$f" ] && continue
  while true; do
    out=$(npx ts-node platforms/blogger/publish.ts "$f" 2>&1)
    if echo "$out" | grep -q "DRAFT ->"; then ok=$((ok+1)); echo "OK   [$ok/$total] $(basename "$f")" >> "$L"; break
    elif echo "$out" | grep -q "exhausted"; then echo "WAIT $(date +%T) quota exhausted at $(basename "$f")" >> "$L"; sleep 600
    else fail=$((fail+1)); echo "FAIL $(basename "$f"): $(echo "$out" | grep -iE 'fatal|error' | head -1 | cut -c1-150)" >> "$L"; break; fi
  done
  sleep 6
done < "$PENDING"
rm -f "$PENDING"
echo "UPLOAD DONE ok=$ok fail=$fail $(date '+%F %T')" >> "$L"

# Drafts whose title was cleaned locally after they were uploaded: push the new title.
# (publish.ts updates by bloggerPostId; published: false keeps them as drafts.)
for f in content/dev/cloud/120-*.md content/dev/cloud/122-*.md content/dev/etc/106-*.md content/dev/etc/114-*.md content/dev/etc/119-*.md; do
  [ -f "$f" ] || continue
  grep -q '^retitled: true' "$f" && continue
  while true; do
    out=$(npx ts-node platforms/blogger/publish.ts "$f" 2>&1)
    if echo "$out" | grep -q "UPDATED"; then sed -i 's/^bloggerPostId: \(.*\)$/bloggerPostId: \1\nretitled: true/' "$f"; echo "RETITLE OK $(basename "$f")" >> "$L"; break
    elif echo "$out" | grep -q "exhausted"; then sleep 600
    else echo "RETITLE FAIL $(basename "$f")" >> "$L"; break; fi
  done
  sleep 6
done
echo "ALL DONE $(date '+%F %T')" >> "$L"
tail -5 "$L"
