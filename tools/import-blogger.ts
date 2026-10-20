// Export every post of a Blogger blog you own into archive markdown.
//
// Lists LIVE, DRAFT and SCHEDULED posts through the Blogger API (ADMIN view),
// converts each body to markdown, downloads the images referenced in it to
// <out>/<postId>/img/*.webp and rewrites the links to those relative paths.
//
// Usage: npx ts-node tools/import-blogger.ts --url https://example.blogspot.com/ --out _archive/example
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
dotenv.config({ path: path.join(__dirname, "..", ".env") });
import { google, blogger_v3 } from "googleapis";
import TurndownService from "turndown";
import sharp from "sharp";
import { getAuthClient } from "../platforms/blogger/auth";

const args = process.argv.slice(2);
const opt = (name: string): string | undefined => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const blogUrl = opt("--url");
const outDir = opt("--out");
if (!blogUrl || !outDir) {
  console.error("Usage: npx ts-node tools/import-blogger.ts --url <blogUrl> --out <dir>");
  process.exit(1);
}

const td = new TurndownService({ headingStyle: "atx", codeBlockStyle: "fenced", bulletListMarker: "-", emDelimiter: "*" });
td.addRule("pre", {
  filter: (node) => node.nodeName === "PRE",
  replacement: (_c, node) => {
    const el = node as HTMLElement;
    const cls = `${el.getAttribute("class") ?? ""} ${el.querySelector("code")?.getAttribute("class") ?? ""}`;
    const lang = (cls.match(/(?:language|lang)-([\w+-]+)/) ?? [])[1] ?? "";
    const text = (el.textContent ?? "").replace(/\r\n/g, "\n").replace(/\n+$/, "");
    return `\n\n\`\`\`${lang}\n${text}\n\`\`\`\n\n`;
  },
});
td.keep((node) => node.nodeName === "TABLE");

const safeName = (s: string): string =>
  s.replace(/[\x00-\x1f\x7f]/g, "").replace(/[\\/:*?"<>|]/g, "").replace(/\s+/g, " ").trim().slice(0, 100) || "untitled";

async function downloadImages(md: string, imgDir: string): Promise<string> {
  const urls = Array.from(new Set(Array.from(md.matchAll(/!\[[^\]]*\]\((https?:\/\/[^)\s]+)\)/g)).map((m) => m[1])));
  if (urls.length === 0) return md;
  fs.mkdirSync(imgDir, { recursive: true });
  let n = 0;
  for (const url of urls) {
    try {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buf = Buffer.from(await res.arrayBuffer());
      const name = `img${n === 0 ? "" : `_${n}`}.webp`;
      await sharp(buf, { animated: true }).webp({ quality: 85 }).toFile(path.join(imgDir, name));
      md = md.split(url).join(`./img/${name}`);
      n++;
    } catch (e) {
      console.warn(`  ! image kept as URL (${(e as Error).message}): ${url.slice(0, 80)}`);
    }
  }
  return md;
}

(async () => {
  const auth = await getAuthClient();
  const blogger = google.blogger({ version: "v3", auth });
  const blog = await blogger.blogs.getByUrl({ url: blogUrl });
  const blogId = blog.data.id!;
  console.log(`blog ${blog.data.name} (${blogId})`);

  const posts: blogger_v3.Schema$Post[] = [];
  let pageToken: string | undefined;
  do {
    const res = await blogger.posts.list({
      blogId,
      status: ["LIVE", "DRAFT", "SCHEDULED"],
      view: "ADMIN",
      maxResults: 100,
      fetchBodies: true,
      pageToken,
    });
    posts.push(...(res.data.items ?? []));
    pageToken = res.data.nextPageToken ?? undefined;
  } while (pageToken);
  console.log(`${posts.length} posts`);

  fs.mkdirSync(outDir, { recursive: true });
  for (const p of posts) {
    const id = p.id!;
    const postDir = path.join(outDir, id);
    fs.mkdirSync(postDir, { recursive: true });
    let md = td.turndown(p.content ?? "").replace(/\n{3,}/g, "\n\n").trim();
    md = await downloadImages(md, path.join(postDir, "img"));
    const title = p.title ?? "";
    const fm = [
      "---",
      `title: ${JSON.stringify(title)}`,
      `labels: ${JSON.stringify(p.labels ?? [])}`,
      "published: false",
      `date: ${(p.published ?? "").slice(0, 10)}`,
      `readerComments: "ALLOW"`,
      `source: "blogger"`,
      `sourceBlog: ${JSON.stringify(blogUrl)}`,
      `sourcePostId: "${id}"`,
      `sourceStatus: ${p.status ?? ""}`,
      `sourceUrl: ${JSON.stringify(p.url ?? "")}`,
      `sourcePublishedAt: ${JSON.stringify(p.published ?? "")}`,
      "---",
      "",
    ].join("\n");
    fs.writeFileSync(path.join(postDir, `${safeName(title)}.md`), fm + md + "\n", "utf8");
    console.log(`${id}\t${p.status}\t${(p.published ?? "").slice(0, 10)}\t${title}`);
  }
})().catch((e: Error) => {
  console.error(e.message);
  process.exit(1);
});
