import dotenv from "dotenv";
import { google, blogger_v3 } from "googleapis";
import { getAuthClient } from "../platforms/blogger/auth";

dotenv.config();

const BLOGS: { name: string; id: string }[] = [
  { name: "dev", id: "3666962477256387094" },
  { name: "language", id: "6585438201171100645" },
];

async function listAllPosts(blogger: blogger_v3.Blogger, blogId: string) {
  const out: { title: string; published: string; url: string; status: string }[] = [];
  let pageToken: string | undefined = undefined;
  do {
    const res: any = await blogger.posts.list({
      blogId,
      status: ["LIVE"],
      maxResults: 100,
      fetchBodies: false,
      pageToken,
    });
    const items = res.data.items ?? [];
    for (const p of items) {
      out.push({
        title: p.title ?? "(no title)",
        published: p.published ?? "(no date)",
        url: p.url ?? "",
        status: p.status ?? "?",
      });
    }
    pageToken = res.data.nextPageToken ?? undefined;
  } while (pageToken);
  return out;
}

(async () => {
  const auth = await getAuthClient();
  const blogger = google.blogger({ version: "v3", auth });

  for (const { name, id } of BLOGS) {
    console.log(`\n=== ${name} (${id}) ===`);
    const posts = await listAllPosts(blogger, id);
    posts.sort((a, b) => a.published.localeCompare(b.published));

    // group by date (YYYY-MM-DD in JST)
    const byDate = new Map<string, string[]>();
    for (const p of posts) {
      const d = new Date(p.published);
      const jst = new Date(d.getTime() + 9 * 60 * 60 * 1000);
      const ymd = jst.toISOString().slice(0, 10);
      if (!byDate.has(ymd)) byDate.set(ymd, []);
      byDate.get(ymd)!.push(p.title);
    }

    console.log(`Total posts: ${posts.length}`);
    console.log(`\nPer date (JST):`);
    const dates = [...byDate.keys()].sort();
    for (const d of dates) {
      const titles = byDate.get(d)!;
      const marker = titles.length > 1 ? ` ⚠️  ${titles.length} posts` : "";
      console.log(`  ${d}${marker}`);
      for (const t of titles) {
        console.log(`    - ${t}`);
      }
    }
  }
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
