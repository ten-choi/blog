// Local preview for content/theme/ten-dev-notes.xml.
//
// Fetches real pages from the live blog, swaps in the CSS from the local theme
// XML (the <b:skin> block with its <Variable> values resolved, plus the plain
// <style> block in <head>), and reloads the browser whenever the XML is saved.
//
// Only CSS changes show up here. Markup changes inside <b:includable> blocks
// need the theme to be uploaded in Blogger (Theme > Edit HTML) to take effect.
//
// Usage: node tools/theme-preview.js   ->  http://localhost:4000

const http = require("http");
const https = require("https");
const fs = require("fs");
const path = require("path");

const BLOG = "https://ten-dev-notes.blogspot.com";
const THEME = path.join(__dirname, "..", "content", "theme", "ten-dev-notes.xml");
const PORT = Number(process.env.PORT) || 4000;

const pageCache = new Map();
const clients = new Set();

function fetchLive(urlPath) {
  if (pageCache.has(urlPath)) return Promise.resolve(pageCache.get(urlPath));
  return new Promise((resolve, reject) => {
    const get = (url, hops) =>
      https
        .get(url, { headers: { "User-Agent": "Mozilla/5.0 theme-preview" } }, (res) => {
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && hops < 5) {
            res.resume();
            return get(new URL(res.headers.location, url).toString(), hops + 1);
          }
          let body = "";
          res.setEncoding("utf8");
          res.on("data", (c) => (body += c));
          res.on("end", () => {
            const page = { status: res.statusCode, type: res.headers["content-type"] || "text/html", body };
            if (res.statusCode === 200) pageCache.set(urlPath, page);
            resolve(page);
          });
        })
        .on("error", reject);
    get(BLOG + urlPath, 0);
  });
}

function readThemeCss() {
  const xml = fs.readFileSync(THEME, "utf8");

  const skinMatch = xml.match(/<b:skin[^>]*><!\[CDATA\[([\s\S]*?)\]\]><\/b:skin>/);
  let skin = skinMatch ? skinMatch[1] : "";

  // Resolve <Variable name="x" value="y"/> and substitute $(x).
  const vars = {};
  for (const m of skin.matchAll(/<Variable\s[^>]*?name="([^"]+)"[^>]*?value="([^"]*)"[^>]*\/>/g)) {
    // type="background" variables refer to their own color attribute as $(color).
    const color = (m[0].match(/\scolor="([^"]*)"/) || [])[1];
    vars[m[1]] = color ? m[2].replace(/\$\(color\)/g, color) : m[2];
  }
  const resolve = (value, depth = 0) =>
    depth > 10 ? value : value.replace(/\$\(([^)]+)\)/g, (all, name) => (name in vars ? resolve(vars[name], depth + 1) : all));
  skin = resolve(skin);

  // The plain <style> block that follows the skin in <head>.
  const afterSkin = skinMatch ? xml.slice(xml.indexOf(skinMatch[0]) + skinMatch[0].length) : xml;
  const headStyle = (afterSkin.match(/^\s*<style>([\s\S]*?)<\/style>/) || [, ""])[1];

  // Custom blocks marked in the XML, plus the hardcoded main menu.
  const block = (name) => (xml.match(new RegExp(`<!-- ten:${name}:start -->[\\s\\S]*?<!-- ten:${name}:end -->`)) || [""])[0];
  const menu = (xml.match(/<ul id='main-menu-nav' role='menubar'>[\s\S]*?<\/ul>/) || [""])[0];

  return { skin, headStyle, headBlock: block("head"), bodyBlock: block("body"), menu };
}

const RELOAD_SCRIPT = `<script>
(function(){var es=new EventSource('/__reload');es.onmessage=function(){location.reload();};})();
</script>`;

function rewrite(html) {
  const { skin, headStyle, headBlock, bodyBlock, menu } = readThemeCss();
  let out = html;

  // Drop blocks the live theme may already contain, then insert the local ones.
  out = out.replace(/<!-- ten:head:start -->[\s\S]*?<!-- ten:head:end -->/, "");
  out = out.replace(/<!-- ten:body:start -->[\s\S]*?<!-- ten:body:end -->/, "");
  out = out.replace("</head>", () => headBlock + "</head>");
  const bodyEnd = out.lastIndexOf("</body>");
  out = out.slice(0, bodyEnd) + bodyBlock + out.slice(bodyEnd);
  if (menu) out = out.replace(/<ul id='main-menu-nav' role='menubar'>[\s\S]*?<\/ul>/, () => menu);

  out = out.replace(/<style id='page-skin-1' type='text\/css'>[\s\S]*?<\/style>/, () =>
    `<style id='page-skin-1' type='text/css'>${skin}</style>`
  );
  // Replace the first attribute-less <style> in <head> (the one after the skin).
  const headEnd = out.indexOf("</head>");
  const idx = out.indexOf("<style>");
  if (idx !== -1 && idx < headEnd) {
    const end = out.indexOf("</style>", idx);
    out = out.slice(0, idx) + `<style>${headStyle}</style>` + out.slice(end + "</style>".length);
  }

  // Keep navigation inside the preview.
  out = out.split(BLOG).join("").split(BLOG.replace("https:", "http:")).join("");
  out = out.replace("</body>", RELOAD_SCRIPT + "</body>");
  return out;
}

const server = http.createServer(async (req, res) => {
  if (req.url === "/__reload") {
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache", Connection: "keep-alive" });
    res.write(": connected\n\n");
    clients.add(res);
    req.on("close", () => clients.delete(res));
    return;
  }
  if (req.url === "/__refetch") {
    pageCache.clear();
    res.writeHead(302, { Location: "/" });
    return res.end();
  }
  try {
    const page = await fetchLive(req.url);
    const isHtml = page.type.includes("text/html");
    res.writeHead(page.status, { "Content-Type": page.type, "Cache-Control": "no-store" });
    res.end(isHtml ? rewrite(page.body) : page.body);
  } catch (e) {
    res.writeHead(502, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("Failed to fetch from the live blog: " + e.message);
  }
});

let timer;
fs.watch(THEME, () => {
  clearTimeout(timer);
  timer = setTimeout(() => {
    console.log(`[${new Date().toLocaleTimeString()}] theme changed, reloading ${clients.size} tab(s)`);
    for (const c of clients) c.write("data: reload\n\n");
  }, 150);
});

server.listen(PORT, () => {
  console.log(`Theme preview: http://localhost:${PORT}`);
  console.log(`Watching ${THEME}`);
  console.log(`Open /__refetch to drop cached pages and pull fresh HTML from the live blog.`);
});
