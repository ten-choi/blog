// Stage the remaining _archive/{dev,data,ten-logged} posts for Blogger drafts.
//
// What it does for every markdown file under those folders:
//   - skips README.md, near-empty notes (< 150 chars) and a few known junk files
//   - normalises front matter (title, labels, published: false, date, readerComments,
//     bloggerPostId) and keeps any extra keys the file already had
//   - assigns a date: a real date from the file if it has one, otherwise a slot
//     inside the blog's empty stretch (2024-03 .. 2026-05) chosen per series so the
//     timeline reads naturally, never earlier than what the content could exist
//     (posts that mention 2026-era AI tooling are dated 2026-10)
//   - moves local / Notion images into the blog-images repo (dev/archive/<slug>/)
//     and rewrites the links to the jsDelivr CDN
//   - writes the file to content/dev/<folder>/ and removes the archive original
//
// Usage: npx ts-node tools/stage-archive.ts [--dry] [--images-repo <path>]
import fs from "fs";
import path from "path";
import { execSync } from "child_process";
import sharp from "sharp";

const CDN = "https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main";
const args = process.argv.slice(2);
const DRY = args.includes("--dry");
let imagesRepo = path.resolve("..", "blog-images");
const ir = args.indexOf("--images-repo");
if (ir >= 0) imagesRepo = path.resolve(args[ir + 1]);

// ---- rules -----------------------------------------------------------------

const SKIP_NAMES = new Set(["README.md"]);
const DELETE = new Set(["_archive/dev/algorithms/leetcode/104.md"]); // duplicate of 15.md (3Sum) under the wrong number
const MIN_CHARS = 150;

const TITLE_FIX: Record<string, string> = {
  // same title as mysql-performance-optimization.md; give the hands-on log its own name
  "_archive/dev/database/mysql optimzize index and algorithm.md": "MySQL Performance Optimization - Hands-on Test with 12 Million Rows",
  "_archive/dev/side-projects/chrome-extension/영단어외우기시스템.md": "영단어 외우기 크롬 익스텐션을 만들었다",
  "_archive/dev/algorithms/leetcode/933. Number of Recent Calls.md": "933. Number of Recent Calls",
  "_archive/dev/algorithms/leetcode/0문제유형.md": "도쿄 영어 환경 IT 대기업 백엔드 코딩테스트 10주 플랜 (Java)",
  "_archive/dev/algorithms/leetcode/1.md": "1. Two Sum",
  "_archive/dev/algorithms/leetcode/15.md": "15. 3Sum",
  "_archive/dev/algorithms/leetcode/153.md": "153. Find Minimum in Rotated Sorted Array",
  "_archive/dev/algorithms/leetcode/200.md": "200. Number of Islands",
  "_archive/dev/algorithms/leetcode/217.md": "217. Contains Duplicate",
  "_archive/dev/algorithms/leetcode/238.md": "238. Product of Array Except Self",
  "_archive/dev/algorithms/leetcode/242.md": "242. Valid Anagram",
  "_archive/dev/algorithms/leetcode/347.md": "347. Top K Frequent Elements",
  "_archive/dev/algorithms/leetcode/424.md": "424. Longest Repeating Character Replacement",
  "_archive/dev/algorithms/leetcode/49.md": "49. Group Anagrams",
  "_archive/dev/algorithms/leetcode/739. Daily Temperatures.md": "739. Daily Temperatures",
  "_archive/dev/algorithms/leetcode/901. Online Stock Span.md": "901. Online Stock Span",
};

// content that cannot predate these months
const FLOORS: [string, RegExp][] = [
  ["2026-06", /claude code|\bfable\b|opus 4\.?5|claude 5|mythos|오르카|\borca\b|herdr|graphify|ponytail|headroom|codex cli|gemini cli/i],
  ["2026-05", /archify/i], // recent diagram tool; keep it just before the first live Blogger post (2026-05-18)
  ["2025-06", /\bmcp\b|model context protocol|agentic|에이전트 도구|vibe coding|바이브 코딩|windsurf|claude 4|sonnet 4|gpt-4\.1|gpt-5/i],
  ["2024-09", /claude 3\.5|gpt-4o|llama 3|react 19|next\.?js 15|python 3\.13|postgres(ql)? 17|mysql 9/i],
  ["2024-03", /\bclaude\b|gpt-4|gpt4|\bllm\b|생성형 ai|generative ai|\brag\b|copilot|java 21|spring boot 3\.2|kotlin 2\.0/i],
];

// series bucket -> window (KST) the slots are spread over; order = reading order
const WINDOWS: Record<string, [string, string]> = {
  network: ["2024-03-04", "2024-09-27"],
  rdb: ["2024-10-02", "2024-12-27"],
  security: ["2025-01-06", "2025-02-27"],
  misc: ["2025-03-03", "2025-04-29"],
  algorithms: ["2025-05-02", "2025-09-29"],
  data: ["2025-10-02", "2025-12-26"],
  "system design": ["2026-01-06", "2026-04-28"],
  ai: ["2026-10-01", "2026-10-06"],
};

const DEFAULT_LABELS: Record<string, string[]> = {
  network: ["Network", "컴퓨터 네트워킹"],
  rdb: ["Database", "SQL Tuning"],
  security: ["Security"],
  algorithms: ["Algorithm", "LeetCode"],
  data: ["Data Engineering"],
  "system design": ["System Design"],
};

function folderOf(rel: string, title: string): string {
  const parts = rel.split("/"); // _archive/<root>/<a>/<b>...
  const root = parts[1];
  if (root === "data") return "data";
  if (root === "ten-logged") {
    if (/aws|api gateway/i.test(title)) return "infra";
    if (/피드백/.test(title)) return "teamwork";
    return "code-design";
  }
  const a = parts[2];
  if (a === "database") return "rdb"; // content/dev/database is the auto-publish queue
  return a; // algorithms, network, security, "system design", side-projects, infra, ...
}

function bucketOf(folder: string, floor: string): string {
  if (floor === "2026-06") return "ai";
  if (WINDOWS[folder]) return folder;
  return "misc";
}

// ---- helpers ---------------------------------------------------------------

type Post = {
  src: string; rel: string; fm: Record<string, string>; fmOrder: string[]; body: string;
  title: string; chars: number; folder: string; floor: string; bucket: string; date: string; fixed: boolean;
};

function parse(raw: string): { fm: Record<string, string>; order: string[]; body: string } {
  raw = raw.replace(/^﻿/, "");
  const m = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!m) return { fm: {}, order: [], body: raw };
  const fm: Record<string, string> = {};
  const order: string[] = [];
  for (const line of m[1].split(/\r?\n/)) {
    const k = line.match(/^([A-Za-z_][\w-]*):\s*(.*)$/);
    if (k) { fm[k[1]] = k[2].trim(); order.push(k[1]); }
  }
  return { fm, order, body: raw.slice(m[0].length) };
}
const unq = (v: string): string => (v.startsWith('"') && v.endsWith('"') ? JSON.parse(v) : v);
const labelsOf = (v: string): string[] => {
  if (!v) return [];
  if (v.startsWith("[")) { try { return JSON.parse(v); } catch { return v.slice(1, -1).split(",").map((s) => s.trim().replace(/^"|"$/g, "")).filter(Boolean); } }
  return v.split(",").map((s) => s.trim()).filter(Boolean);
};
const safeName = (s: string): string => s.replace(/[\x00-\x1f\x7f]/g, "").replace(/[\\/:*?"<>|]/g, "").replace(/\s+/g, " ").trim().slice(0, 100);
const slug = (s: string): string => s.toLowerCase().replace(/[^a-z0-9가-힣]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 60) || "post";

// deterministic pseudo-random so re-runs produce the same plan
let seed = 20261013;
const rnd = (): number => { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; };

const pad = (n: number): string => String(n).padStart(2, "0");
function kst(ms: number): string {
  const d = new Date(ms + 9 * 3600e3);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:00+09:00`;
}
function slotDates(from: string, to: string, n: number): string[] {
  const a = Date.parse(`${from}T00:00:00+09:00`), b = Date.parse(`${to}T00:00:00+09:00`);
  const step = n > 1 ? (b - a) / (n - 1) : 0;
  const out: string[] = [];
  for (let i = 0; i < n; i++) {
    const day = Math.floor((a + i * step + (rnd() - 0.5) * step * 0.5) / 864e5) * 864e5;
    const minutes = 9 * 60 + Math.floor(rnd() * 13 * 60); // 09:00 - 21:59 KST
    out.push(kst(day - 9 * 3600e3 + minutes * 60e3));
  }
  return out;
}
function toRfc(d: string): string {
  if (/^\d{4}-\d{2}-\d{2}$/.test(d)) return `${d}T10:00:00+09:00`;
  return Number.isNaN(Date.parse(d)) ? "" : d;
}

function walk(d: string): string[] {
  return fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : e.name.endsWith(".md") ? [path.join(d, e.name)] : []));
}
function remove(p: string): void {
  if (DRY) return;
  try { execSync(`git ls-files --error-unmatch "${p}"`, { stdio: "ignore" }); execSync(`git rm -rq "${p}"`); }
  catch { fs.rmSync(p, { recursive: true, force: true }); }
}

async function moveImages(post: Post): Promise<string> {
  const dir = path.dirname(post.src);
  const dst = path.join(imagesRepo, "dev", "archive", slug(path.basename(post.src, ".md")));
  let body = post.body;
  const refs = Array.from(body.matchAll(/!\[[^\]]*\]\(([^)\s]+)\)/g)).map((m) => m[1]);
  let n = 0;
  for (const ref of Array.from(new Set(refs))) {
    let buf: Buffer | null = null;
    if (/^https?:\/\//.test(ref)) {
      if (!/notion\.site/.test(ref)) continue; // keep CDN / stable hosts as they are
      try { const r = await fetch(ref); if (r.ok) buf = Buffer.from(await r.arrayBuffer()); } catch { /* keep url */ }
    } else {
      const local = path.resolve(dir, ref);
      if (fs.existsSync(local)) buf = fs.readFileSync(local);
      else console.warn(`  ! missing local image, link kept: ${post.rel} -> ${ref}`);
    }
    if (!buf) continue;
    const name = `img${n === 0 ? "" : `_${n}`}.webp`;
    n++;
    if (!DRY) {
      fs.mkdirSync(dst, { recursive: true });
      await sharp(buf, { animated: true }).webp({ quality: 85 }).toFile(path.join(dst, name));
    }
    body = body.split(ref).join(`${CDN}/dev/archive/${slug(path.basename(post.src, ".md"))}/${name}`);
  }
  return body;
}

// ---- main ------------------------------------------------------------------

(async () => {
  const posts: Post[] = [];
  for (const root of ["_archive/dev", "_archive/data", "_archive/ten-logged"]) {
    if (!fs.existsSync(root)) continue;
    for (const src of walk(root)) {
      const rel = src.split(path.sep).join("/");
      if (DELETE.has(rel)) { console.log(`delete  ${rel}`); remove(src); continue; }
      if (SKIP_NAMES.has(path.basename(src))) { console.log(`skip    ${rel} (readme)`); continue; }
      const raw = fs.readFileSync(src, "utf8");
      const { fm, order, body } = parse(raw);
      const chars = body.replace(/!\[[^\]]*\]\([^)]*\)/g, "").replace(/\s+/g, "").length;
      if (chars < MIN_CHARS) { console.log(`skip    ${rel} (${chars} chars)`); continue; }
      const title = TITLE_FIX[rel] ?? unq(fm.title ?? "") ?? "";
      if (!title) { console.log(`skip    ${rel} (no title)`); continue; }
      let floor = "";
      for (const [ym, re] of FLOORS) if (re.test(raw)) { floor = ym; break; }
      const folder = folderOf(rel, title);
      const given = toRfc(unq(fm.date ?? "") || unq(fm.sourcePublishedAt ?? ""));
      posts.push({ src, rel, fm, fmOrder: order, body, title, chars, folder, floor, bucket: bucketOf(folder, floor), date: given, fixed: !!given });
    }
  }

  // assign slot dates per bucket, in natural file order (series numbering)
  const collator = new Intl.Collator("en", { numeric: true });
  for (const bucket of Object.keys(WINDOWS)) {
    const group = posts.filter((p) => p.bucket === bucket && !p.fixed).sort((a, b) => collator.compare(a.rel, b.rel));
    const [from, to] = WINDOWS[bucket];
    const dates = slotDates(from, to, group.length);
    group.forEach((p, i) => { p.date = dates[i]; });
  }
  // never earlier than the content allows
  for (const p of posts) if (p.floor && p.date.slice(0, 7) < p.floor) {
    console.warn(`  ! ${p.rel}: date ${p.date.slice(0, 10)} is before floor ${p.floor}; moved to floor`);
    p.date = `${p.floor}-15T10:00:00+09:00`;
  }

  posts.sort((a, b) => a.date.localeCompare(b.date));
  console.log(`\n${posts.length} posts to stage${DRY ? " (dry run)" : ""}\n`);
  for (const p of posts) {
    const body = await moveImages(p);
    const labels = labelsOf(p.fm.labels ?? p.fm.tags ?? "");
    const finalLabels = labels.length ? labels : DEFAULT_LABELS[p.folder] ?? [];
    const keep = p.fmOrder.filter((k) => !["title", "labels", "tags", "published", "date", "readerComments", "bloggerPostId", "cover_image", "series", "description"].includes(k));
    const fmLines = [
      `title: ${JSON.stringify(p.title)}`,
      `labels: ${JSON.stringify(finalLabels)}`,
      "published: false",
      `date: ${p.date}`,
      `readerComments: "ALLOW"`,
      `bloggerPostId: `,
      ...keep.map((k) => `${k}: ${p.fm[k]}`),
      ...(p.fm.source ? [] : [`source: "archive"`, `archivePath: ${JSON.stringify(p.rel)}`]),
    ];
    const dstDir = path.join("content", "dev", p.folder);
    const dst = path.join(dstDir, `${safeName(p.title)}.md`);
    console.log(`${p.date.slice(0, 10)}  ${p.bucket.padEnd(13)} ${p.fixed ? "*" : " "} ${p.folder.padEnd(13)} ${p.title.slice(0, 60)}`);
    if (DRY) continue;
    fs.mkdirSync(dstDir, { recursive: true });
    fs.writeFileSync(dst, `---\n${fmLines.join("\n")}\n---\n${body.trimEnd()}\n`, "utf8");
    remove(p.rel.startsWith("_archive/ten-logged/") ? path.dirname(p.src) : p.src);
  }
})().catch((e: Error) => { console.error(e); process.exit(1); });
