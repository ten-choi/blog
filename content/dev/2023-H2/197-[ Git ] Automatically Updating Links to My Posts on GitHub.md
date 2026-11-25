---
title: "[ Git ] Automatically Updating Links to My Posts on GitHub"
labels: ["ETC","Git","jp","readme","GitHub","Archive"]
published: true
date: 2023-11-23T11:23:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 197
tistoryUrl: "https://yeolceo.tistory.com/197"
tistoryCategory: "ETC/Git"
tistoryTags: ["jp","readme","GitHub","github"]
tistoryPostedAt: "2023-11-23 11:23:11"
language: en
bloggerPostId: "4108368534904063932"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/197/img.webp)

## **Environment**

node v20

vscode

javascript

GitHub Actions

An RSS link for your blog or Twitter

## **What Is GitHub Actions?**

GitHub Actions is a continuous integration and continuous delivery (CI/CD) platform that lets you automate your build, test, and deployment pipeline.

You can create workflows that build and test every pull request to your repository,

or deploy merged pull requests to production.

## **Creating the GitHub Action**

First, create a repository with the same name as your GitHub username.

Once it's created, go to Settings > Actions > General in that repository.

GitHub Actions needs permission to push, so select the top option.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/197/img_1.webp)

It's easier to follow along with the [documentation](https://docs.github.com/ko/actions/deployment/about-deployments/deploying-with-github-actions) open.

Clone the repository you just created.

Then create the folder and file from the root directory: ".github/workflows/github-action.yml"

Copy and paste the code below into that file.

This is what will act as the scheduler, pulling in your blog links and so on from now on.

```yaml
# name of the workflow
name: GitHub Actions For My Profile
# when to run it
on:
  push:
    branches:
      - master
  # run via cron once a day
  schedule:
    - cron: "0 0 * * *"

# the units the workflow runs
jobs:
  #job name
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "? This job is now running on a ${{ runner.os }} server hosted by GitHub!"
      - run: echo "? The name of your branch is ${{ github.ref }} and your repository is ${{ github.repository }}."
      - name: Setup Node
        uses: actions/checkout@v4
      - uses: actions/setup-node@v3
        with:
          node-version: 20
          cache: npm
      - name: Install dependencies
        run: npm ci
      - name: Update README
        run: npm start
      - name: Commit files
        run: |
          git config --local user.email "github-actions[bot]@users.noreply.github.com"
          git config --local user.name "github-actions[bot]"
          git add .
          git commit -a -m "Fix: update README.md"
      - name: Push changes
        uses: ad-m/github-push-action@master
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          branch: ${{ github.ref }}
```

## **Creating readmeUpdate.js, Run by the Scheduler**

Run npm init in the VS Code terminal.

```bash
npm init -y
npm i rss-parser
```

Then in the generated package.json, change the test entry under scripts to start.

```json
"scripts": {
    "start": "node readmeUpdate.js"
  },
```

Create a file called readmeUpdate.js. This file generates the README.

The scheduler runs it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/197/img_2.webp)

```typescript
import { writeFileSync } from "node:fs";
import Parser from "rss-parser";

// my blog link
const blogLink = ` https://yeolceo.tistory.com/rss`;

/**
 * the text that becomes README.MD
 * @type {string}
 */
let text = `# ? Hi there 
My name is TenChoi
I work as a server programmer
<br />

<a href="https://github.com/ten-log">
  <img align="center" src="https://github-readme-stats-theta-gules-17.vercel.app/api?username=ten-log&show_icons=true&theme=dark&line_height=20"/>
</a>
<br />
<br />
<div>
<img src="https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white" alt="TS and typescript"/>
<img src="https://img.shields.io/badge/Express.js-404D59?style=for-the-badge" alt="white jester shoe icon"/> <br/>
<img src="https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=openjdk&logoColor=white" alt="java"/>
<img src="https://img.shields.io/badge/Spring-6DB33F?style=for-the-badge&logo=spring&logoColor=white" alt="spring"/>
</div>

### ? Latest Blog Posts
`;

(async () => {
  // create the rss-parser and use it to fetch the feed
  const parser = new Parser({
    headers: {
      Accept: "application/rss+xml, application/xml, text/xml; q=0.1",
    },
  });
  const feed = await parser.parseURL(blogLink);

  // grab the title and link of the latest posts and append them to text
  for (let i = 0; i < 7; i++) {
    const { title, link } = feed.items[i];
    console.log(`${i + 1}`);
    console.log(`${title}`);
    console.log(`${link}`);
    text += `</br>${i + 1}. <a href=${link}>${title}</a>`;
  }

  // create or update README.md
  writeFileSync("README.md", text, "utf8", (e) => {
    console.log(e);
  });

  console.log("updated");
})();

/* 
For showing the stack I've worked with so far
<a href="https://github.com/ten-log">
  <img align="center" src="https://github-readme-stats-theta-gules-17.vercel.app/api/top-langs?username=ten-log&layout=compact&theme=dark" />
</a>
<br /> */
```

As long as you have the information, you can organize and manage it in your GitHub README like this.

References

[https://docs.github.com/ko/actions/quickstart](https://docs.github.com/ko/actions/quickstart)

[https://yueliang-front-end.tistory.com/9](https://yueliang-front-end.tistory.com/9)
