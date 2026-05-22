const fs = require('fs');
const FILE = 'C:/workSpace/projects/personal/blog/blogs/dev/theme/agent-coder/agent-coder.xml';

const lines = fs.readFileSync(FILE, 'utf8').split(/\r?\n/);
const formatted = fs.readFileSync('C:/workSpace/projects/personal/blog/pagination_formatted.js', 'utf8').trimEnd();

// find the eval-packer line (must be the pagination one — already verified to be only one left)
let idx = -1;
for (let i = 0; i < lines.length; i++) {
  if (lines[i].startsWith('eval(function(p,a,c,k,e,d)')) { idx = i; break; }
}
if (idx === -1) { console.error('packer not found'); process.exit(1); }
console.log('Patching line', idx + 1);

// Replace the single packed line with the formatted multi-line content
lines.splice(idx, 1, ...formatted.split('\n'));
fs.writeFileSync(FILE, lines.join('\n'));
console.log('New line count:', lines.length);
