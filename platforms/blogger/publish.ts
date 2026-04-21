import fs from "fs";
import path from "path";
import dotenv from "dotenv";
import frontMatter from "front-matter";
import { google, blogger_v3 } from "googleapis";
import { marked } from "marked";
import { getAuthClient } from "./auth";

dotenv.config();

interface PostAttributes {
  title?: string;
  published?: boolean;
  description?: string;
  tags?: string | string[];
  cover_image?: string;
  series?: string;
  [key: string]: any;
}

interface PublishOptions {
  blogId: string;
  filePath: string;
  blogger: blogger_v3.Blogger;
}

function parseTags(tags?: string | string[]): string[] {
  if (!tags) return [];
  if (Array.isArray(tags)) return tags.map((t) => String(t).trim()).filter(Boolean);
  return String(tags)
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
}

function markdownToHtml(md: string): string {
  marked.setOptions({ gfm: true, breaks: false });
  return marked.parse(md, { async: false }) as string;
}

async function resolveBlogId(blogger: blogger_v3.Blogger): Promise<string> {
  const idFromEnv = process.env.BLOGGER_BLOG_ID;
  if (idFromEnv) return idFromEnv;

  const urlFromEnv = process.env.BLOGGER_BLOG_URL;
  if (urlFromEnv) {
    const res = await blogger.blogs.getByUrl({ url: urlFromEnv });
    if (!res.data.id) {
      throw new Error(`Blogger API returned no id for url ${urlFromEnv}`);
    }
    return res.data.id;
  }

  throw new Error(
    "Set BLOGGER_BLOG_ID or BLOGGER_BLOG_URL in .env. Run `npm run blogger:blogs` to list your blogs."
  );
}

async function publishOne(opts: PublishOptions): Promise<void> {
  const { blogId, filePath, blogger } = opts;
  console.log(`\nPublishing ${filePath} ...`);

  const fileContent = fs.readFileSync(filePath, "utf8");
  const { attributes, body } = frontMatter<PostAttributes>(fileContent);

  if (!attributes.title) {
    throw new Error(`Missing 'title' in front matter: ${filePath}`);
  }

  const isDraft = attributes.published === false || attributes.published === undefined;
  const html = markdownToHtml(body);
  const labels = parseTags(attributes.tags);

  const requestBody: blogger_v3.Schema$Post = {
    kind: "blogger#post",
    title: attributes.title,
    content: html,
  };
  if (labels.length > 0) requestBody.labels = labels;

  const res = await blogger.posts.insert({
    blogId,
    isDraft,
    requestBody,
  });

  const status = isDraft ? "DRAFT" : "PUBLISHED";
  console.log(`  ${status} -> ${res.data.url || "(no url)"} (id: ${res.data.id})`);
}

function findMarkdownFiles(dir: string): string[] {
  const results: string[] = [];
  for (const name of fs.readdirSync(dir)) {
    const full = path.join(dir, name);
    const stat = fs.statSync(full);
    if (stat.isDirectory()) {
      results.push(...findMarkdownFiles(full));
    } else if (name.endsWith(".md")) {
      results.push(full);
    }
  }
  return results;
}

async function listBlogs(blogger: blogger_v3.Blogger): Promise<void> {
  const res = await blogger.blogs.listByUser({ userId: "self" });
  const items = res.data.items || [];
  if (items.length === 0) {
    console.log("No blogs found for this account.");
    return;
  }
  console.log("Your blogs:");
  for (const b of items) {
    console.log(`  - ${b.name}`);
    console.log(`      id : ${b.id}`);
    console.log(`      url: ${b.url}`);
  }
  console.log("\nSet BLOGGER_BLOG_ID in .env to the id you want to target.");
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const auth = await getAuthClient();
  const blogger = google.blogger({ version: "v3", auth });

  if (args.includes("--list-blogs")) {
    await listBlogs(blogger);
    return;
  }

  const blogId = await resolveBlogId(blogger);
  const positional = args.filter((a) => !a.startsWith("--"));

  if (positional.length > 0) {
    for (const arg of positional) {
      await publishOne({ blogId, blogger, filePath: path.resolve(arg) });
    }
    return;
  }

  const postsDir = path.join(__dirname, "..", "..", "published");
  if (!fs.existsSync(postsDir)) {
    throw new Error(`published directory not found at ${postsDir}`);
  }
  const files = findMarkdownFiles(postsDir);
  console.log(`Found ${files.length} markdown files.`);
  for (const f of files) {
    try {
      await publishOne({ blogId, blogger, filePath: f });
    } catch (e) {
      console.error(`  failed: ${(e as Error).message}`);
    }
  }
}

main().catch((e) => {
  console.error("Fatal:", (e as Error).message);
  process.exit(1);
});
