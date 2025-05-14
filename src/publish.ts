import dotenv from "dotenv";
import fs from "fs";
import path from "path";
import frontMatter from "front-matter";

// Load environment variables
dotenv.config();

const API_KEY = process.env.DEVTO_TOKEN_PROD;
const API_URL = "https://dev.to/api/articles";

if (!API_KEY) {
  console.error("Error: DEVTO_TOKEN_PROD is not set in .env file.");
  process.exit(1);
}

interface DevToArticle {
  title: string;
  published: boolean;
  body_markdown: string;
  description?: string;
  tags?: string[];
  series?: string | null;
  main_image?: string;
}

interface DevToResponse {
  id: number;
  url: string;
  status?: string;
  [key: string]: any;
}

interface PostAttributes {
  title: string;
  published?: boolean;
  description?: string;
  tags?: string;
  cover_image?: string;
  series?: string;
  [key: string]: any;
}

async function publishArticle(filePath: string): Promise<DevToResponse> {
  console.log(`Publishing ${filePath}...`);

  try {
    // Read the markdown file
    const fileContent = fs.readFileSync(filePath, "utf8"); // Parse front matter and content
    const { attributes, body } = frontMatter<PostAttributes>(fileContent);

    // Prepare the article data
    const articleData = {
      article: {
        title: attributes.title,
        published: attributes.published || false,
        body_markdown: fileContent,
        description: attributes.description,
        tags: attributes.tags
          ? attributes.tags.split(",").map((tag: string) => tag.trim())
          : [],
        series: attributes.series || null,
      } as DevToArticle,
    };

    if (attributes.cover_image) {
      articleData.article.main_image = attributes.cover_image;
    }

    // Send the article to dev.to API
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": API_KEY as string,
      },
      body: JSON.stringify(articleData),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(
        `API Error: ${response.status} - ${JSON.stringify(errorData)}`
      );
    }

    const data = (await response.json()) as DevToResponse;
    console.log(
      `Successfully published! Article URL: https://dev.to/article/${data.id}`
    );
    return data;
  } catch (error) {
    console.error(`Error publishing ${filePath}:`, (error as Error).message);
    throw error;
  }
}

async function main(): Promise<void> {
  const postsDir = path.join(__dirname, "..", "posts");

  // Check if specific file is provided as command line argument
  const specificFile = process.argv[2];

  if (specificFile) {
    const filePath = path.resolve(specificFile);
    await publishArticle(filePath);
    return;
  }
  // Otherwise publish all markdown files in the posts directory
  try {
    // 재귀적으로 모든 마크다운 파일 찾기
    const findMarkdownFiles = (dir: string): string[] => {
      let results: string[] = [];
      const list = fs.readdirSync(dir);

      list.forEach((file) => {
        const filePath = path.join(dir, file);
        const stat = fs.statSync(filePath);

        if (stat.isDirectory()) {
          // 하위 디렉토리 검색
          results = results.concat(findMarkdownFiles(filePath));
        } else if (file.endsWith(".md")) {
          // 마크다운 파일 추가
          results.push(filePath);
        }
      });

      return results;
    };

    const markdownFiles = findMarkdownFiles(postsDir);
    console.log(`Found ${markdownFiles.length} markdown files to publish.`);

    for (const filePath of markdownFiles) {
      await publishArticle(filePath);
    }
  } catch (error) {
    console.error("Error publishing articles:", (error as Error).message);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Unhandled error:", err);
  process.exit(1);
});
