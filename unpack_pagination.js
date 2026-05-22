// Unpack the pagination eval(function(p,a,c,k,e,d){...}) on a target line.
const fs = require('fs');
const FILE = 'C:/workSpace/projects/personal/blog/blogs/dev/theme/agent-coder/agent-coder.xml';
const lines = fs.readFileSync(FILE, 'utf8').split(/\r?\n/);

// Find the line index (0-based) of the eval packer
let evalIdx = -1;
for (let i = 0; i < lines.length; i++) {
  if (lines[i].startsWith('eval(function(p,a,c,k,e,d)')) { evalIdx = i; break; }
}
if (evalIdx === -1) { console.error('No packer line found'); process.exit(1); }
console.log('Found packer at line', evalIdx + 1);

const src = lines[evalIdx];
const m = src.match(/\}\('([\s\S]*)',\s*(\d+),\s*(\d+),\s*'([\s\S]*?)'\.split\('\|'\)/);
if (!m) { console.error('regex did not match'); process.exit(1); }

let payload = m[1];
const base = parseInt(m[2]);
const count = parseInt(m[3]);
const keys = m[4].split('|');

// Decode string-literal escapes in the payload (it's a JS single-quoted string)
payload = payload
  .replace(/\\\\/g, '\\')
  .replace(/\\'/g, "'")
  .replace(/\\n/g, '\n')
  .replace(/\\t/g, '\t')
  .replace(/\\r/g, '\r');

function unpack(p, b, c, k) {
  return p.replace(/\b\w+\b/g, (w) => {
    let n = 0;
    for (const ch of w) {
      let v;
      if (ch >= '0' && ch <= '9') v = ch.charCodeAt(0) - 48;
      else if (ch >= 'a' && ch <= 'z') v = ch.charCodeAt(0) - 87;       // a=10 .. z=35
      else if (ch >= 'A' && ch <= 'Z') v = ch.charCodeAt(0) - 29;       // A=36 .. Z=61
      else return w;
      if (v >= b) return w;
      n = n * b + v;
    }
    if (n < c && k[n]) return k[n];
    return w;
  });
}

let out = unpack(payload, base, count, keys);

// Apply twice — the packer can replace a key with another token that is also a key
let prev;
do { prev = out; out = unpack(out, base, count, keys); } while (out !== prev);

console.log('Unpacked length:', out.length);
console.log('Sample (first 400):', out.slice(0, 400));

// Sanity check: must not contain redirects to known bad domains, and must be valid-looking JS
const bad = ['soratemplates', 'window.location=', 'location.href=', 'location.replace'];
for (const b of bad) {
  if (out.includes(b)) console.log('NOTE: contains', b);
}

fs.writeFileSync('C:/workSpace/projects/personal/blog/pagination_unpacked.js', out);
console.log('\nWrote pagination_unpacked.js — review before patching into XML.');
