// Convert a Tistory backup folder into archive markdown.
//
// Tistory's backup ("관리 > 블로그 > 데이터 관리 > 백업") produces one folder
// per post: <id>/<id>-<slug>.html plus <id>/img/*. This tool turns each post
// into <out>/<id>/<id>-<slug>.md with frontmatter in this repo's convention,
// converts the post's images to WebP next to it (<out>/<id>/img/*.webp) and
// rewrites the image links to those relative paths.
//
// Usage: npx ts-node tools/import-tistory.ts <backupDir> [outDir]
//   outDir defaults to _archive/tistory
import fs from "fs";
import path from "path";
import TurndownService from "turndown";
import sharp from "sharp";

const backupDir = process.argv[2];
const outDir = process.argv[3] ?? path.join("_archive", "tistory");
if (!backupDir || !fs.existsSync(backupDir)) {
  console.error("Usage: npx ts-node tools/import-tistory.ts <backupDir> [outDir]");
  process.exit(1);
}

// --- HTML helpers ----------------------------------------------------------

const decode = (s: string): string =>
  s
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .trim();

function textOf(html: string, re: RegExp): string {
  const m = html.match(re);
  return m ? decode(m[1].replace(/<[^>]+>/g, "")) : "";
}

// Inner HTML of <div class="contents_style">, found by tracking div depth so
// nested divs inside the post body do not end the match early.
function bodyHtml(html: string): string {
  const open = html.indexOf('<div class="contents_style">');
  if (open < 0) return "";
  let i = open + '<div class="contents_style">'.length;
  let depth = 1;
  const tag = /<\/?div\b[^>]*>/g;
  tag.lastIndex = i;
  let m: RegExpExecArray | null;
  while ((m = tag.exec(html))) {
    depth += m[0].startsWith("</") ? -1 : 1;
    if (depth === 0) return html.slice(i, m.index);
  }
  return html.slice(i);
}

// --- Markdown conversion ---------------------------------------------------

const td = new TurndownService({
  headingStyle: "atx",
  codeBlockStyle: "fenced",
  bulletListMarker: "-",
  emDelimiter: "*",
});

// Tistory code blocks: <pre class="<lang> ..."><code>...</code></pre>
td.addRule("tistoryCode", {
  filter: (node) => node.nodeName === "PRE",
  replacement: (_content, node) => {
    const el = node as HTMLElement;
    const cls = (el.getAttribute("class") ?? "").trim().split(/\s+/)[0] ?? "";
    const lang = cls && !/^code_/.test(cls) ? cls : "";
    const code = decode(el.innerHTML.replace(/^<code[^>]*>/, "").replace(/<\/code>$/, "").replace(/<br\s*\/?>/gi, "\n").replace(/<[^>]+>/g, ""))
      .replace(/\r\n/g, "\n")
      .replace(/\n+$/, "");
    return `\n\n\`\`\`${lang}\n${code}\n\`\`\`\n\n`;
  },
});

// <figure class="imageblock"> <span><img src=./img/x.png></span> <figcaption>..</figcaption></figure>
td.addRule("tistoryFigure", {
  filter: (node) => node.nodeName === "FIGURE",
  replacement: (_content, node) => {
    const el = node as HTMLElement;
    const img = el.querySelector("img");
    if (!img) return "";
    const src = img.getAttribute("src") ?? "";
    const cap = decode(el.querySelector("figcaption")?.textContent ?? "");
    return `\n\n![${cap}](${src})\n\n`;
  },
});

// Keep tables as HTML (turndown core has no table rule); strip inline styling.
td.keep((node) => node.nodeName === "TABLE");

// --- Image conversion ------------------------------------------------------

async function convertImages(srcImgDir: string, dstImgDir: string): Promise<Map<string, string>> {
  const map = new Map<string, string>(); // original basename -> new basename
  if (!fs.existsSync(srcImgDir)) return map;
  fs.mkdirSync(dstImgDir, { recursive: true });
  // Tistory can hold img.png and img.jpg in one post; both would become
  // img.webp, so suffix the original extension when a name is already taken.
  const used = new Set<string>();
  const webpName = (name: string): string => {
    const base = path.basename(name, path.extname(name));
    let out = `${base}.webp`;
    if (used.has(out.toLowerCase())) out = `${base}-${path.extname(name).slice(1).toLowerCase()}.webp`;
    used.add(out.toLowerCase());
    return out;
  };
  for (const name of fs.readdirSync(srcImgDir)) {
    const ext = path.extname(name).toLowerCase();
    const src = path.join(srcImgDir, name);
    if (ext === ".webp") {
      const out = webpName(name);
      fs.copyFileSync(src, path.join(dstImgDir, out));
      map.set(name, out);
    } else if (ext === ".png" || ext === ".jpg" || ext === ".jpeg" || ext === ".gif") {
      const out = webpName(name);
      try {
        await sharp(src, { animated: ext === ".gif" }).webp({ quality: 85 }).toFile(path.join(dstImgDir, out));
        map.set(name, out);
      } catch (e) {
        console.warn(`  ! could not convert ${src}: ${(e as Error).message}; copying as-is`);
        fs.copyFileSync(src, path.join(dstImgDir, name));
        map.set(name, name);
      }
    } else {
      fs.copyFileSync(src, path.join(dstImgDir, name));
      map.set(name, name);
    }
  }
  return map;
}

// --- Misc ------------------------------------------------------------------

function detectLanguage(text: string): "ko" | "ja" | "en" {
  const hangul = (text.match(/[가-힯]/g) ?? []).length;
  const kana = (text.match(/[぀-ヿ]/g) ?? []).length;
  if (hangul === 0 && kana === 0) return "en";
  return kana > hangul ? "ja" : "ko";
}

const safeName = (s: string): string =>
  s.replace(/[\x00-\x1f\x7f]/g, "").replace(/[\\/:*?"<>|]/g, "").replace(/\s+/g, " ").trim().slice(0, 100);

const yamlStr = (s: string): string => JSON.stringify(s);

// --- Main ------------------------------------------------------------------

(async () => {
  const ids = fs
    .readdirSync(backupDir, { withFileTypes: true })
    .filter((e) => e.isDirectory() && /^\d+$/.test(e.name))
    .map((e) => Number(e.name))
    .sort((a, b) => a - b);

  const summary: string[] = [];
  let imgCount = 0;

  for (const id of ids) {
    const dir = path.join(backupDir, String(id));
    const htmlFile = fs.readdirSync(dir).find((f) => f.endsWith(".html"));
    if (!htmlFile) {
      console.warn(`${id}: no html, skipped`);
      continue;
    }
    const html = fs.readFileSync(path.join(dir, htmlFile), "utf8");
    const title = textOf(html, /<h2 class="title-article">([\s\S]*?)<\/h2>/) || `untitled-${id}`;
    const category = textOf(html, /<p class="category">([\s\S]*?)<\/p>/);
    const dateTime = textOf(html, /<p class="date">([\s\S]*?)<\/p>/);
    const tags = textOf(html, /<div class="tags">([\s\S]*?)<\/div>/)
      .split(/\s+/)
      .filter((t) => t.startsWith("#"))
      .map((t) => t.slice(1));

    const postOut = path.join(outDir, String(id));
    fs.mkdirSync(postOut, { recursive: true });
    const imgMap = await convertImages(path.join(dir, "img"), path.join(postOut, "img"));
    imgCount += imgMap.size;

    let md = td.turndown(bodyHtml(html));
    // rewrite ./img/<name> -> ./img/<converted name>
    md = md.replace(/\]\(\.\/img\/([^)]+)\)/g, (_m, name: string) => `](./img/${imgMap.get(name) ?? name})`);
    // collapse runs of blank/nbsp-only lines
    md = md
      .replace(/^[  ]+$/gm, "")
      .replace(/\n{3,}/g, "\n\n")
      .trim();

    const language = detectLanguage(md);
    const isPrivate = /비공개/.test(title);
    const labels = Array.from(new Set([...category.split("/").map((s) => s.trim()).filter(Boolean), ...tags]));

    const fm = [
      "---",
      `title: ${yamlStr(title)}`,
      `labels: ${JSON.stringify(labels)}`,
      "published: false",
      `date: ${dateTime.slice(0, 10)}`,
      `readerComments: "ALLOW"`,
      `source: "tistory"`,
      `tistoryId: ${id}`,
      `tistoryUrl: "https://yeolceo.tistory.com/${id}"`,
      `tistoryCategory: ${yamlStr(category)}`,
      `tistoryTags: ${JSON.stringify(tags)}`,
      `tistoryPostedAt: ${yamlStr(dateTime)}`,
      `language: ${language}`,
      isPrivate ? "private: true" : null,
      "---",
      "",
    ]
      .filter((l) => l !== null)
      .join("\n");

    const mdName = `${id}-${safeName(title)}.md`;
    fs.writeFileSync(path.join(postOut, mdName), fm + md + "\n", "utf8");
    summary.push(`${String(id).padStart(3)}\t${dateTime.slice(0, 10) || "-"}\t${language}\t${category || "-"}\t${imgMap.size} img\t${title}${isPrivate ? " [private]" : ""}`);
  }

  console.log(summary.join("\n"));
  console.log(`\n${summary.length} posts, ${imgCount} images -> ${outDir}`);
})().catch((e: Error) => {
  console.error(e);
  process.exit(1);
});
