# How to Manage Medium Posts in Git as Markdown Files

I wanted to create a tech blog that I can manage with **Markdown** and **GitHub**.
I’ve been considering **Medium** because it supports **Markdown** and is one of the most popular blogging platforms, which makes it an appealing choice.
For a simple and lightweight setup, I thought **Node.js** would be a great fit. Plus, it offers an official SDK (**medium-sdk-nodejs**), which seemed like the best option for my needs.

If you want to view the source code comfortably, please refer to the Git repository at the bottom of the page.

**Tech Stack**

- Node.js v22.9.0
- TypeScript
- VSCode
- Git
- Notion

## Setting Up the Project

1. **Notion Setup**  
   First, I set up a Notion account to store images.
   You need to set it to publish mode to ensure that the image links do not expire.
   Additionally, make sure to use the image addresses from the view site, not from your logged-in Notion account.
2. **Create Git Repository**  
   Then, I created a new Git repository to keep everything version-controlled.
3. **Configure VSCode**  
   Next, I opened VSCode and configured a few basic settings, such as enabling "Format on Save" for a smoother workflow.
4. **VSCode Extension**  
   Next, install the **Markdown All in One** extension, which helps with document creation using shortcuts.
5. **Running Commands with Bash**  
   Finally, I ran the necessary commands using **Bash**.

**Running Commands with Bash**

```bash
npm --init
npx tsc --init

npm i axios
npm i dotenv
npm i medium-sdk

npm i -D tsx
npm i -D @types/dotenv
npm i -D typescript
```

**TypeScript Setup**

I wrote and executed the code in TypeScript, so I also installed the necessary dependencies.
To run the code directly from the terminal, I needed to install `tsx` globally.
Additionally, I set up the JSON configuration and modified the script to run it using the `npm run dev` command.

```json
{
  "name": "medium-stories-node",
  "version": "1.0.0",
  "description": "I wanna handle medium on git",
  "main": "src/main_ts.ts",
  "type": "module",
  "author": "yoru_choi",
  "license": "ISC",
  "scripts": {
    "dev": "tsx src/main.ts"
  },
  "dependencies": {
    "axios": "^1.7.7",
    "dotenv": "^16.4.5",
    "medium-sdk": "^0.0.4"
  },
  "devDependencies": {
    "@types/dotenv": "^6.1.1",
    "tsx": "^4.19.1",
    "typescript": "^5.6.2"
  }
}
```

## Let's Start

![NotionImage](https://qlqjs674.notion.site/image/https%3A%2F%2Fprod-files-secure.s3.us-west-2.amazonaws.com%2F6ab3efe6-44b5-4e5c-9d86-56543fb7f59d%2F3418b9be-911a-41f2-a2fc-faf472dd3371%2Fimage.png?table=block&id=11a930ff-582f-8022-9e77-f75410ec09d3&spaceId=6ab3efe6-44b5-4e5c-9d86-56543fb7f59d&width=700&userId=&cache=v2)

**The URL for creating an integration token for a Medium blog**: [MediumSecurityUrl](https://medium.com/me/settings/security)

![NotionImage](https://qlqjs674.notion.site/image/https%3A%2F%2Fprod-files-secure.s3.us-west-2.amazonaws.com%2F6ab3efe6-44b5-4e5c-9d86-56543fb7f59d%2Fb3fd5609-9abd-401f-ac06-f649e63940e1%2Fimage.png?table=block&id=115930ff-582f-80b9-997b-dfaa46fa3cc8&spaceId=6ab3efe6-44b5-4e5c-9d86-56543fb7f59d&width=710&userId=&cache=v2)

I'll create the folder and file structure as shown above. There will be two folders: `src` and `stories`.

- `src` folder will be used for posting articles.
- `stories` folder will be used to store and manage all the articles.

First, I'll explain the stories part

## Stories Part

I use the folder name as an ID to link `src` and `stories`.
For better findability, I make the title and folder name the same..

In the `stories` directory, there is a folder for each article. The folder name is the title of the article. For this article, the folder name would be **How to Manage Medium Posts in Git as Markdown Files**.
Inside the folder, there are two files: `config.ts` and `post.md`.

- `config.ts` is where you define the settings necessary for the article.
- `post.md` is where you write the article in markdown format for posting.

You can refer to the sample below for more details.

```typescript
const articleId = "";
const title = "How to manage Medium posts in Git as Markdown files";
const tags = ["medium", "git", "markdown", "typescript", "medium-sdk-nodejs"];
export default { articleId, title, tags };
```

`articleId` is a variable that stores the ID returned when the article is created.
I may not use it often, but I'll keep it as a variable for now, as I don't know how the ID value might be used in the future.
`title` refers to the article's title.
`tags` are the article's associated tags.

**Title** is an ID that checks the relationship between `src` and the `stories`.
It is also used as the title for the Notion page where images are uploaded.

Now that we've covered the `stories` part, let's move on to the execution part in `src`.

## Src Part

There are three main sections: `main`, `interface`, and `mediumService`.
Let's begin by taking a look at the `interface`.

**Interface**

```typescript
export interface PostCreationConfig {
  accessToken: string; // Notion integration token
  folderName: string; // Title of the post
  actionType: "get" | "create" | "update"; // Action type: get, create (no update or delete API available)
  publishStatus: "draft" | "public" | "unlisted"; // Publish status from Medium
}

export interface PostConfig {
  postId?: string; // Medium article ID when using the medium-node-sdk to post
  title: string; // Title of the post
  tags: string[]; // Tags associated with the post
}
```

**Main**

```typescript
import dotenv from "dotenv";
import { PostCreationConfig } from "./interface";
import { getMediumPost, createMediumPost } from "./mediumService";

dotenv.config();

// You only need to modify the postCreationConfig when deploying, and then deploy.
const postCreationConfig: PostCreationConfig = {
  accessToken: process.env.TEST_MEDIUM_TOKEN!, // set token
  folderName: "How to manage Medium posts in Git as Markdown files", // set folder name
  actionType: "create", // what to do
  publishStatus: "draft",
};

switch (postCreationConfig.actionType) {
  case "get":
    getMediumPost(postCreationConfig);
    break;
  case "create":
    createMediumPost(postCreationConfig);
    break;
  case "update":
    console.log(
      [
        "You would create a post in Markdown format.",
        "Then, check the content of the post created on Medium and copy it.",
        "After that, paste it into the post you want to edit.",
      ].join("\n")
    );
    break;
  default:
    console.log("nothing run");
}
```

**postCreationConfig** setup, the token value is retrieved from `.env`, and you can perform both get and post actions on articles.

Since **Medium** does not support update or delete operations, after some consideration, I concluded that the only way to modify an article is to publish it as a draft as many times as needed, and once satisfied with the changes, simply copy and paste the content.

**mediumService**

Features to use for **Medium** posting

```typescript
export const getMediumPost = async (generateConfig: PostCreationConfig) => {
  const userId = await getMediumUserId(generateConfig.accessToken);
  await getPost(userId, generateConfig);
};

export const createMediumPost = async (generateConfig: PostCreationConfig) => {
  const userId = await getMediumUserId(generateConfig.accessToken);
  const markdownPost = await getMarkdownPost(generateConfig.folderName);
  await createPost(userId, markdownPost, generateConfig);
};
```

Retrieve user information from Medium using a integration token

```typescript
// Retrieve user information from Medium using a integration token
const getMediumUserId = async (token: String): Promise<string> => {
  const userResponse: AxiosResponse = await axios.get(
    `${mediumApiBaseUrl}/me`,
    {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    }
  );
  return userResponse.data.data.id;
};
```

get medium post

```typescript
async function getPost(
  userId: string,
  generateConfig: PostCreationConfig
): Promise<void> {
  try {
    const response: AxiosResponse = await axios.get(
      `${mediumApiBaseUrl}/users/${userId}/publications`,
      {
        headers: {
          Authorization: `Bearer ${generateConfig.accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );
    console.log("Post got successfully:", response.data);
  } catch (err: any) {
    console.error(
      "Error getting post:",
      err.response ? err.response.data : err.message
    );
  }
}
```

Fetch the content of the article

```typescript
const getMarkdownPost = async (folderName: string): Promise<string> => {
  const path = `stories/${folderName}/post.md`;
  return await fs.readFile(path, "utf8");
};
```

Posting a article to a **Medium**

```typescript
async function createPost(
  userId: string,
  markdownPost: string,
  generateConfig: PostCreationConfig
): Promise<void> {
  try {
    const contentFormat: string = "markdown";
    const postConfig: PostConfig = await import(
      `../stories/${generateConfig.folderName}/config.ts`
    ).then((data) => {
      return data.default;
    });
    const response: AxiosResponse = await axios.post(
      `${mediumApiBaseUrl}/users/${userId}/posts`,
      {
        title: postConfig.title,
        contentFormat: contentFormat,
        content: markdownPost,
        publishStatus: generateConfig.publishStatus,
        tags: postConfig.tags,
      },
      {
        headers: {
          Authorization: `Bearer ${generateConfig.accessToken}`,
          "Content-Type": "application/json",
        },
      }
    );
    console.log("Post created successfully:", response.data);
  } catch (err: any) {
    console.error(
      "Error creating post:",
      err.response ? err.response.data : err.message
    );
  }
}
```

## Digression

**Things to consider when writing a blog**

- **For Future Reference :** I want to make sure the content can serve as a useful reference for myself later.
- **Sharing Knowledge :** The goal is to share knowledge in a way that's easy for others to understand.

**Thoughts While Writing**

- I looked into Medium's code block settings to make information easier to read, but when generating posts via the SDK, syntax highlighting was not applied to code blocks.
- I considered using **GitHub Gist** or **CodePen**, but it seemed inconvenient when writing the post. Instead, I opted for sharing a Git repository Url.
- It was inconvenient to manually add syntax highlighting for Node.js, Npm, and TypeScript. I tried automating it, but there were just too many keywords involved. My compromise was using keyboard shortcuts to apply the highlighting with a VSCode extension.
- In previous tech blogs, I wrote posts directly on the blog. However, moving forward, I want to adopt a more developer-friendly approach like the methods mentioned above.

Feedback is always welcome.

**Reference**  
[Medium SDK for Node.js](https://github.com/Medium/medium-sdk-nodejs)  
[Medium API Docs](https://github.com/Medium/medium-api-docs)

**Git Repository**  
[Medium Git Repository](https://github.com/yoru-choi/medium-stories-node/tree/dev)  
[This Post Git Repository](https://github.com/yoru-choi/medium-stories-node/blob/dev/stories/How%20to%20manage%20Medium%20posts%20in%20Git%20as%20Markdown%20files/post.md)
