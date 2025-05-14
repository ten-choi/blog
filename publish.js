require("dotenv").config();
const fs = require("fs");
const path = require("path");
const frontMatter = require("front-matter");

const API_KEY = process.env.DEVTO_API_KEY;
const API_URL = "https://dev.to/api/articles";

if (!API_KEY) {
  console.error("Error: DEVTO_API_KEY is not set in .env file.");
  process.exit(1);
}

async function publishArticle(filePath) {
  console.log(`Publishing ${filePath}...`);

  try {
    // Read the markdown file
    const fileContent = fs.readFileSync(filePath, "utf8");

    // Parse front matter and content
    const { attributes, body } = frontMatter(fileContent);

    // Prepare the article data
    const articleData = {
      article: {
        title: attributes.title,
        published: attributes.published || false,
        body_markdown: fileContent,
        description: attributes.description,
        tags: attributes.tags
          ? attributes.tags.split(",").map((tag) => tag.trim())
          : [],
        series: attributes.series || null,
      },
    };

    if (attributes.cover_image) {
      articleData.article.main_image = attributes.cover_image;
    }

    // Send the article to dev.to API
    const response = await fetch(API_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "api-key": API_KEY,
      },
      body: JSON.stringify(articleData),
    });

    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(
        `API Error: ${response.status} - ${JSON.stringify(errorData)}`
      );
    }

    const data = await response.json();
    console.log(
      `Successfully published! Article URL: https://dev.to/article/${data.id}`
    );
    return data;
  } catch (error) {
    console.error(`Error publishing ${filePath}:`, error.message);
    throw error;
  }
}

async function main() {
  const postsDir = path.join(__dirname, "posts");

  // Check if specific file is provided as command line argument
  const specificFile = process.argv[2];

  if (specificFile) {
    const filePath = path.resolve(specificFile);
    await publishArticle(filePath);
    return;
  }

  // Otherwise publish all markdown files in the posts directory
  try {
    const files = fs.readdirSync(postsDir);
    for (const file of files) {
      if (file.endsWith(".md")) {
        const filePath = path.join(postsDir, file);
        await publishArticle(filePath);
      }
    }
  } catch (error) {
    console.error("Error publishing articles:", error.message);
    process.exit(1);
  }
}

main();
