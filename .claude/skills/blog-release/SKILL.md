---
name: blog-release
description: Publish a draft markdown file from blogs/<dev|language>/drafts/ to Google Blogger with labels, then git-move the file to published/ and commit. Use when the user wants to release, publish, or deploy a blog post.
---

# Blog Release

End-to-end workflow for releasing a post from this repo to Google Blogger.

## Inputs

1. **Blog target** — `dev` or `language`. If not given, ask the user.
2. **Source file** — path under `blogs/<target>/drafts/`. If not given, list drafts and ask the user to pick.

## Blog ID mapping

- `dev` → `$env:BLOGGER_BLOG_ID_DEV` (3666962477256387094)
- `language` → `$env:BLOGGER_BLOG_ID_LANGUAGE` (6585438201171100645)

The base `BLOGGER_BLOG_ID` is intentionally absent from `.env`. This skill injects it at runtime by mapping the target to the correct suffixed variable. **Do not add `BLOGGER_BLOG_ID` back to `.env`.**

## Auth (first run only)

Auth is handled by `platforms/blogger/auth.ts`, which `publish.ts` invokes automatically. Behavior:

- If `BLOGGER_REFRESH_TOKEN` is present in `.env`, it's used silently — no user action.
- If absent (first run, or after a manual delete), the publish command will print:
  - An OAuth URL
  - "Waiting for redirect on http://localhost:<port> ..."
  - The user opens that URL in a browser, signs in, and authorizes.
  - On success, `auth.ts` writes the new `BLOGGER_REFRESH_TOKEN` back into `.env` automatically. No `token.json` file is created.

**If the publish command appears to hang on "Waiting for redirect on ...":** this means you (Claude) ran the command and it is now waiting for the user. Print the auth URL to the user and tell them to authorize in a browser. Do not kill the process — once they complete it, the publish continues.

If the refresh_token in `.env` is rejected (revoked, scope changed, etc.), delete the `BLOGGER_REFRESH_TOKEN` line from `.env` and re-run — that triggers a fresh OAuth flow.

## Steps

### 1. Identify the target blog

If the user's request didn't specify, ask: which blog — `dev` or `language`?

### 2. Find the draft file

If the user gave a file path, use it. Otherwise list drafts and ask:

- Use Glob with `blogs/<target>/drafts/**/*.md`
- Present the list, ask which to publish

### 3. Read and propose labels

Read the file. Note the existing `tags:` in frontmatter if any — use as baseline.

Analyze the markdown body and propose 3–6 labels. **Labels are not decorative — they are search keywords.** Every label should be something a real reader might type into Google or Blogger's search box to find this kind of post. Optimize for discoverability, not for self-expression.

Good labels:
- Concrete, named topics people actually search for: `JLPT`, `일본어 독학`, `JavaScript 비동기`, `React Hooks`, `PostgreSQL 인덱스`
- Specific technologies, tools, frameworks, certifications: `TypeScript`, `Vim`, `Docker`, `TOEIC`
- Established method or pattern names: `객체지향`, `Clean Architecture`, `섀도잉`

Avoid:
- Mood/abstract tags with no search volume: `꾸준함`, `성장`, `회고`, `생각`, `일상`
- Overly broad single words that match anything: `공부`, `개발`, `프로그래밍`, `언어` (these need a qualifier — `웹 개발` is fine, bare `개발` is not)
- Tags that every post on this blog would have (the blog's own theme is already discoverable via the blog itself — don't waste a label slot on it)
- Made-up phrases that no one searches for: `나의 일본어 동행`, `평생의 러닝메이트`

Aim for a mix:
- 2–3 **specific keyword labels** (this is the SEO core — most important)
- 1–2 **broader category labels** that group the post with related content (e.g. `외국어 학습법`, `백엔드`)
- At most 1 **format/audience label** if it's genuinely useful for filtering (`초보`, `튜토리얼`)

For Korean blogs, prefer Korean keywords for Korean-language content, but keep technology/product names in their canonical form (`React`, not `리액트`; `JLPT`, not `일본어 능력 시험`).

Show the proposed labels with a one-line reason per label (which search term it targets), and ask for confirmation or edits before applying.

### 4. Update frontmatter

**Default behavior: populate every applicable field below, not just the required ones.** The Optional fields exist precisely because Blogger's API supports them — leaving them blank wastes the metadata. Only skip an optional field if it doesn't apply to this post (e.g. no specific publish date is needed).

For each optional field, propose a value and confirm with the user (alongside the labels confirmation in step 3) rather than silently omitting it.

**Required:**
- `title:` — required by `publish.ts`. If missing, ask the user.
- `labels: [label1, label2, ...]` — the approved labels from step 3. `tags:` is accepted as a legacy synonym (publish.ts reads `labels` first, falls back to `tags`). Prefer `labels` for new posts.
- `published: true` — boolean. `true` = visible post, `false`/absent = uploaded as a Blogger draft.

**Optional (publish.ts supports these):**
- `date: 2026-05-22T14:55:00+09:00` — RFC3339 datetime. Sets the post's published timestamp on Blogger. If absent, Blogger stamps the time of the API call. Useful for backdating imported posts.
- `readerComments: "ALLOW"` — comment policy. Exact allowed values: `ALLOW`, `DONT_ALLOW`, `DONT_ALLOW_HIDE_EXISTING`. publish.ts validates and rejects others.

**Auto-managed (do not set by hand):**
- `bloggerPostId: "1591..."` — the Blogger post ID. publish.ts writes this to the file's front matter on first successful insert. Its presence is what makes the next `publish.ts` run perform an **update** instead of a new **insert**. Do not edit or remove unless you intentionally want to fork into a new post.

For actual SEO meta-description behavior, write a strong opening paragraph in the body — Blogger's `all-head-content` include auto-generates `<meta name="description">` from the post snippet (first ~150 chars), and Google's snippet generation reads from there.

Use Edit to update frontmatter. Preserve all existing fields that aren't being changed.

### 5. Publish to Blogger

`publish.ts` reads `BLOGGER_BLOG_ID` from `process.env`. The `.env` file only has the suffixed variants (`_DEV` / `_LANGUAGE`) — these are *not* injected into your PowerShell session automatically (dotenv only runs inside the Node process, not the shell that launches it). So you must set `BLOGGER_BLOG_ID` directly in the PowerShell command, hardcoding the actual ID from the mapping above:

For the **dev** blog:
```powershell
$env:BLOGGER_BLOG_ID = "3666962477256387094" ; npm run publish:blogger -- "<absolute file path>"
```

For the **language** blog:
```powershell
$env:BLOGGER_BLOG_ID = "6585438201171100645" ; npm run publish:blogger -- "<absolute file path>"
```

Both statements must be on the same line (joined by `;`) so the env var lives in the same shell invocation as `npm`.

**Insert vs update is automatic**, decided by the file's front matter:

- No `bloggerPostId` in front matter → `posts.insert`. On success, publish.ts writes `bloggerPostId: "..."` back into the file's front matter. The terminal output shows `PUBLISHED -> <url> (id: ...)` and `bloggerPostId saved to front matter`.
- `bloggerPostId` present → `posts.update`. The post on Blogger is overwritten in place (title, content, labels, readerComments, etc. are all replaced from the file). Terminal output shows `UPDATED -> <url> (id: ...)`.

If the run was an `UPDATED`, the file is already in `published/` (was moved there on its original release). **Skip step 6 — there's no move to do.** Go straight to step 7.

Read the command output:
- Success line looks like `PUBLISHED -> https://...blogspot.com/... (id: ...)`. Save the URL to report at the end.
- If it errors, **stop**. Report the error and do not proceed to step 6.

### 6. Move drafts/ → published/

**Skip this step if the run was an UPDATE** (file is already under `published/`).

Compute the destination by mirroring the subpath:

- Source: `blogs/<target>/drafts/<subpath>/<file>.md`
- Destination: `blogs/<target>/published/<subpath>/<file>.md`

Create the destination directory if it doesn't exist, then `git mv`:

```powershell
New-Item -ItemType Directory -Force "<dest dir>" | Out-Null
git mv "<source>" "<destination>"
```

### 7. Commit

Stage **only the post file** — never `git add -A` here. `.env` may have just been touched by the auth flow, other untracked files may exist, and `.gitignore` may have unrelated edits. A blanket add would scoop those up.

For a new release (insert):
```powershell
git add "<destination file path>"
git commit -m "publish(<target>): <short post title>"
```

For a re-publish (update):
```powershell
git add "<file path under published/>"
git commit -m "update(<target>): <short post title> — <what changed>"
```

Keep the commit message title concise (under ~70 chars). If the post title is long, paraphrase. Do not push — the user reviews and pushes themselves.

### 8. Report

Summarize in 1–2 lines:
- Published URL
- New file location

## Edge cases

- If the file already has `published: true` and is still in `drafts/`, treat it as ready to release — skip re-asking about that flag, but still confirm labels.
- If `tags:` is a comma-separated string instead of an array, `publish.ts` accepts both — don't force a format change unless the user wants it.
- If `npm run publish:blogger` reports "no id found", the env var wasn't carried into the subprocess. Re-run the publish line as a single PowerShell statement (no separate `$env:` line followed by a new prompt).
- If `git mv` fails because the destination already exists, ask the user — they may have a stale published copy that needs resolving.
