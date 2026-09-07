import fs from "fs";
import path from "path";
import { spawnSync } from "child_process";
import frontMatter from "front-matter";

interface Attributes {
  title?: string;
  published?: boolean;
  [key: string]: unknown;
}

function markdownFiles(dir: string): string[] {
  const files: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) files.push(...markdownFiles(fullPath));
    else if (entry.isFile() && entry.name.toLowerCase().endsWith(".md")) files.push(fullPath);
  }
  return files.sort((a, b) => a.localeCompare(b));
}

function output(name: string, value: string): void {
  const outputPath = process.env.GITHUB_OUTPUT;
  if (!outputPath) return;
  fs.appendFileSync(outputPath, `${name}<<AUTO_PUBLISH_EOF\n${value}\nAUTO_PUBLISH_EOF\n`, "utf8");
}

function setPublishedFalse(filePath: string): void {
  const content = fs.readFileSync(filePath, "utf8");
  const updated = content.replace(/^(---\r?\n[\s\S]*?\r?\npublished:)\s*true(\s*$)/m, "$1 false$2");
  if (updated === content) throw new Error(`Could not restore published: false in ${filePath}`);
  fs.writeFileSync(filePath, updated, "utf8");
}

function main(): void {
  const args = process.argv.slice(2);
  const dirArg = args[args.indexOf("--dir") + 1];
  if (!dirArg || dirArg.startsWith("--")) throw new Error("Usage: auto-publish-next.ts --dir <directory> [--dry-run]");

  const dir = path.resolve(dirArg);
  if (!fs.existsSync(dir)) throw new Error(`Directory not found: ${dir}`);

  const candidate = markdownFiles(dir).find((filePath) => {
    const parsed = frontMatter<Attributes>(fs.readFileSync(filePath, "utf8"));
    return parsed.attributes.published === false;
  });

  if (!candidate) {
    console.log("Queue empty");
    output("published", "false");
    return;
  }

  const parsed = frontMatter<Attributes>(fs.readFileSync(candidate, "utf8"));
  const title = String(parsed.attributes.title ?? path.basename(candidate, ".md"));
  output("file", path.relative(process.cwd(), candidate));
  output("title", title);
  console.log(`Selected: ${candidate}`);
  console.log(`Title: ${title}`);

  if (args.includes("--dry-run")) {
    output("published", "false");
    return;
  }

  const original = fs.readFileSync(candidate, "utf8");
  const flipped = original.replace(/^(---\r?\n[\s\S]*?\r?\npublished:)\s*false(\s*$)/m, "$1 true$2");
  if (flipped === original) throw new Error(`Could not set published: true in ${candidate}`);
  fs.writeFileSync(candidate, flipped, "utf8");

  const tsNodeCli = require.resolve("ts-node/dist/bin.js");
  const result = spawnSync(process.execPath, [tsNodeCli, "platforms/blogger/publish.ts", candidate], {
    cwd: process.cwd(),
    stdio: "inherit",
  });
  if (result.error) {
    setPublishedFalse(candidate);
    throw new Error(`Could not start Blogger publisher: ${result.error.message}`);
  }
  if (result.status !== 0) {
    setPublishedFalse(candidate);
    throw new Error(`Blogger publish failed with exit code ${result.status ?? "unknown"}`);
  }

  output("published", "true");
}

try {
  main();
} catch (error) {
  console.error(`Fatal: ${(error as Error).message}`);
  process.exit(1);
}
