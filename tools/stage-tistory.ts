// Stage archived Tistory posts for Blogger publishing.
//
// For each post id:
//   - copies _archive/tistory/<id>/img/* into <blog-images>/dev/tistory/<id>/
//   - rewrites image links to the jsDelivr CDN URL for that path
//   - cleans the title ("... -YEOL" suffix), sets published: false (draft on
//     Blogger; --live publishes immediately) and turns the original Tistory
//     timestamp into an RFC3339 `date` (KST) so Blogger keeps the original date
//     even for drafts
//   - moves the markdown into content/dev/<folder>/ (folder from the Tistory
//     category) and deletes the archive folder
//
// Images must then be committed and pushed in the blog-images repo before the
// post is published, e.g.
//   npx ts-node platforms/blogger/publish.ts "content/dev/<folder>/<file>.md"
//
// Usage: npx ts-node tools/stage-tistory.ts [--images-repo <path>] <id> [<id> ...]
import fs from "fs";
import path from "path";

const CDN = "https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main";
const ARCHIVE = path.join("_archive", "tistory");
const CONTENT = path.join("content", "dev");

// Tistory top-level category -> content/dev folder
// "DB" deliberately does not map to content/dev/database: the auto-publish
// workflow treats every `published: false` file there as its queue.
const FOLDER: Record<string, string> = {
  "TS, JS": "javascript",
  DB: "rdb",
  ThirdParty: "etc",
  "IDE, Editor": "etc",
  ForeignLanguage: "language",
  OS: "os",
  Cloud: "cloud",
  CodingTest: "algorithms",
  Python: "python",
  "Java, Kotlin": "java",
  Architecture: "architecture",
  TroubleShooting: "troubleshooting",
  Branding: "career",
  Office: "etc",
  ETC: "etc",
};

const args = process.argv.slice(2);
let imagesRepo = path.resolve("..", "blog-images");
const ids: number[] = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--images-repo") imagesRepo = path.resolve(args[++i]);
  else if (/^\d+$/.test(args[i])) ids.push(Number(args[i]));
}
if (ids.length === 0 || !fs.existsSync(imagesRepo)) {
  console.error("Usage: npx ts-node tools/stage-tistory.ts [--images-repo <path>] <id> [<id> ...]");
  process.exit(1);
}

const cleanTitle = (t: string): string =>
  t
    .replace(/\s*-+\s*YEOL\s*$/i, "") // "... -YEOL"
    .replace(/\s*-+\s*YEOL\s+(?=\()/i, " ") // "... - YEOL (english title)"
    .replace(/\(\s+/g, "(").replace(/\s+\)/g, ")")
    .replace(/\s{2,}/g, " ")
    .trim();

const safeName = (s: string): string =>
  s.replace(/[\x00-\x1f\x7f]/g, "").replace(/[\\/:*?"<>|]/g, "").replace(/\s+/g, " ").trim().slice(0, 100);

function getField(fm: string, key: string): string {
  const m = fm.match(new RegExp(`^${key}:\\s*(.*)$`, "m"));
  if (!m) return "";
  const v = m[1].trim();
  return v.startsWith('"') ? JSON.parse(v) : v;
}

function setField(fm: string, key: string, value: string): string {
  const line = `${key}: ${value}`;
  return new RegExp(`^${key}:.*$`, "m").test(fm) ? fm.replace(new RegExp(`^${key}:.*$`, "m"), line) : `${fm}\n${line}`;
}

for (const id of ids) {
  const srcDir = path.join(ARCHIVE, String(id));
  const mdName = fs.existsSync(srcDir) ? fs.readdirSync(srcDir).find((f) => f.endsWith(".md")) : undefined;
  if (!mdName) {
    console.error(`${id}: not found under ${ARCHIVE}, skipped`);
    continue;
  }
  const raw = fs.readFileSync(path.join(srcDir, mdName), "utf8");
  const m = raw.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/);
  if (!m) {
    console.error(`${id}: no front matter, skipped`);
    continue;
  }
  let fm = m[1];
  let body = raw.slice(m[0].length);

  const category = getField(fm, "tistoryCategory");
  const top = category.split("/")[0].trim();

  // images -> blog-images repo, links -> CDN
  const imgSrc = path.join(srcDir, "img");
  if (fs.existsSync(imgSrc)) {
    const imgDst = path.join(imagesRepo, "dev", "tistory", String(id));
    fs.mkdirSync(imgDst, { recursive: true });
    for (const f of fs.readdirSync(imgSrc)) fs.copyFileSync(path.join(imgSrc, f), path.join(imgDst, f));
  }
  body = body.replace(/\]\(\.\/img\/([^)]+)\)/g, (_s, name: string) => `](${CDN}/dev/tistory/${id}/${name})`);

  // front matter
  const title = cleanTitle(getField(fm, "title"));
  const posted = getField(fm, "tistoryPostedAt"); // "YYYY-MM-DD HH:mm:ss" (KST)
  const rfc = posted.replace(" ", "T") + "+09:00";
  if (Number.isNaN(Date.parse(rfc))) throw new Error(`${id}: bad tistoryPostedAt "${posted}"`);
  fm = setField(fm, "title", JSON.stringify(title));
  // labels: split "TS, JS/react" into parts (Blogger uses commas as separators),
  // drop the KR language marker, dedupe case/punctuation variants (node.js ~ Node.js)
  const category0 = getField(fm, "tistoryCategory");
  const tags: string[] = JSON.parse(getField(fm, "tistoryTags") || "[]");
  const seen = new Set<string>();
  const labels: string[] = [];
  for (const l of [...category0.split(/[/,]/).map((s) => s.trim()).filter(Boolean), ...tags]) {
    const k = l.toLowerCase().replace(/[.\s]/g, "");
    if (k === "kr" || seen.has(k)) continue;
    seen.add(k);
    labels.push(l);
  }
  fm = setField(fm, "labels", JSON.stringify(labels));
  // default: upload to Blogger as a draft (published: false); pass --live to publish immediately
  fm = setField(fm, "published", args.includes("--live") ? "true" : "false");
  fm = setField(fm, "date", rfc);
  if (!/^bloggerPostId:/m.test(fm)) fm = setField(fm, "bloggerPostId", "");

  const folder = FOLDER[top] ?? "etc";
  const dstDir = path.join(CONTENT, folder);
  fs.mkdirSync(dstDir, { recursive: true });
  const dst = path.join(dstDir, `${id}-${safeName(title)}.md`);
  fs.writeFileSync(dst, `---\n${fm}\n---\n${body}`, "utf8");
  fs.rmSync(srcDir, { recursive: true, force: true });
  console.log(`${id}\t${rfc}\t${dst}`);
}
