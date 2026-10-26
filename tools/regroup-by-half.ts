// Regroup content/dev/<category>/*.md into content/dev/<YYYY>-H1|H2/ by post date (KST).
//
// The date comes from the front-matter `date`; posts without one (live posts
// published before dates were tracked) use the Blogger `published` time.
// Moves with `git mv`. Dry run unless --apply.
//
// Usage: npx ts-node tools/regroup-by-half.ts [--apply]
import fs from "fs";
import path from "path";
import { execFileSync } from "child_process";
import { google } from "googleapis";
import { getAuthClient } from "../platforms/blogger/auth";

const ROOT = path.join("content", "dev");
const HALF = /^\d{4}-H[12]$/;

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else if (e.name.endsWith(".md")) out.push(p);
  }
  return out;
}

const half = (iso: string): string => {
  const kst = new Date(Date.parse(iso) + 9 * 3600 * 1000); // shift to KST, read as UTC
  return `${kst.getUTCFullYear()}-H${kst.getUTCMonth() < 6 ? 1 : 2}`;
};

(async () => {
  const apply = process.argv.includes("--apply");
  const files = walk(ROOT).filter((f) => !HALF.test(path.basename(path.dirname(f))));
  const blogger = google.blogger({ version: "v3", auth: await getAuthClient() });
  const blogId = process.env.BLOGGER_BLOG_ID_DEV!;

  const plan: [string, string][] = [];
  for (const f of files) {
    const fm = fs.readFileSync(f, "utf8").match(/^---\r?\n([\s\S]*?)\r?\n---/)?.[1] ?? "";
    let date = fm.match(/^date:\s*"?(\d{4}-\d{2}-\d{2}T[^"\s]+)/m)?.[1];
    if (!date) {
      const id = fm.match(/^bloggerPostId:\s*"?(\d+)/m)?.[1];
      if (!id) throw new Error(`${f}: no date and no bloggerPostId`);
      const r = await blogger.posts.get({ blogId, postId: id, view: "ADMIN" } as any);
      date = (r.data as any).published as string;
    }
    plan.push([f, path.join(ROOT, half(date), path.basename(f))]);
  }

  const seen = new Map<string, string>();
  for (const [src, dst] of plan) {
    if (seen.has(dst) || fs.existsSync(dst)) throw new Error(`collision: ${dst}\n  ${seen.get(dst) ?? dst}\n  ${src}`);
    seen.set(dst, src);
  }

  const count: Record<string, number> = {};
  for (const [, dst] of plan) count[path.basename(path.dirname(dst))] = (count[path.basename(path.dirname(dst))] ?? 0) + 1;
  console.log(Object.entries(count).sort().map(([k, v]) => `${k}\t${v}`).join("\n"));
  console.log(`total ${plan.length}`);
  if (!apply) return;

  for (const [src, dst] of plan) {
    fs.mkdirSync(path.dirname(dst), { recursive: true });
    execFileSync("git", ["mv", src, dst]);
  }
  console.log("moved");
})();
