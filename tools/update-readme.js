// Regenerates the post index in README.md from the live Blogger feed.
// Usage: node tools/update-readme.js
const fs = require("fs");
const path = require("path");

const BLOG = "https://ten-dev-notes.blogspot.com";
const README = path.join(__dirname, "..", "README.md");
const START = "<!-- posts:start -->";
const END = "<!-- posts:end -->";

async function fetchAll() {
  let all = [];
  for (let start = 1; ; start += 150) {
    const res = await fetch(`${BLOG}/feeds/posts/summary?alt=json&max-results=150&start-index=${start}`);
    const data = await res.json();
    const entries = (data.feed && data.feed.entry) || [];
    all = all.concat(entries);
    if (entries.length < 150) break;
  }
  return all.map((e) => ({
    title: e.title.$t.trim(),
    url: e.link.find((l) => l.rel === "alternate").href,
    date: new Date(e.published.$t).toLocaleDateString("sv-SE", { timeZone: "Asia/Seoul" }),
    archive: (e.category || []).some((c) => c.term === "Archive"),
  }));
}

const esc = (s) => s.replace(/([\[\]|])/g, "\\$1");

function byYear(posts) {
  const groups = new Map();
  for (const p of posts) {
    const y = p.date.slice(0, 4);
    if (!groups.has(y)) groups.set(y, []);
    groups.get(y).push(p);
  }
  return [...groups.entries()].sort((a, b) => b[0].localeCompare(a[0]));
}

function list(posts) {
  return posts.map((p) => `- [${esc(p.title)}](${p.url}) <sub>${p.date}</sub>`).join("\n");
}

function render(posts) {
  const current = posts.filter((p) => !p.archive);
  const archive = posts.filter((p) => p.archive);
  const out = [];
  out.push(`_${posts.length} posts in total: ${current.length} current, ${archive.length} in the archive. Last updated ${new Date().toISOString().slice(0, 10)}._`, "");
  out.push(`## Posts (${current.length})`, "");
  for (const [year, items] of byYear(current)) {
    out.push(`### ${year}`, "", list(items), "");
  }
  out.push(`## Archive (${archive.length})`, "");
  out.push("Earlier notes, originally written in Korean (2020 onward) and translated into English. Kept as a record of how I got here.", "");
  for (const [year, items] of byYear(archive)) {
    out.push(`<details>`, `<summary><b>${year}</b> (${items.length})</summary>`, "", list(items), "", `</details>`, "");
  }
  return out.join("\n").trim();
}

(async () => {
  const posts = await fetchAll();
  posts.sort((a, b) => b.date.localeCompare(a.date));
  const readme = fs.readFileSync(README, "utf8");
  const s = readme.indexOf(START), e = readme.indexOf(END);
  if (s < 0 || e < 0) throw new Error("README markers not found");
  const next = readme.slice(0, s + START.length) + "\n" + render(posts) + "\n" + readme.slice(e);
  fs.writeFileSync(README, next);
  console.log(`README updated with ${posts.length} posts`);
})();
