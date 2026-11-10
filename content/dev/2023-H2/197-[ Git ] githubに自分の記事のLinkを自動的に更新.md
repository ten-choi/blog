---
title: "[ Git ] githubに自分の記事のLinkを自動的に更新"
labels: ["ETC","Git","jp","readme","GitHub"]
published: true
date: 2023-11-23T11:23:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 197
tistoryUrl: "https://yeolceo.tistory.com/197"
tistoryCategory: "ETC/Git"
tistoryTags: ["jp","readme","GitHub","github"]
tistoryPostedAt: "2023-11-23 11:23:11"
language: ja
bloggerPostId: "4108368534904063932"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/197/img.webp)

## **Environment**

node v20

vscode

javascript

githubAction

自分のblogやツイッターのrssリンク

## **GithubActionとは**

GitHub Actions は、ビルド、テスト、デプロイのパイプラインを自動化できる継続的インテグレーションと

継続的デリバリー (CI/CD) のプラットフォームです。 リポジトリに対するすべての pull request を

ビルドしてテストしたり、マージされた pull request を運用環境にデプロイしたりするワークフローを作成できます。

## **GithubActionを作る**

まず自分のgithubのnickNameとおなじ名前のrepositoryをつくります。

作った後にはそのrepositoryでsettingのactionのgeneralをクリックします 。

githubActionがpushを同作するためにはpermissionが必要です。一番上のもので選択します。

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/197/img_1.webp)

[Document](https://docs.github.com/ko/actions/deployment/about-deployments/deploying-with-github-actions)を見ながら参考するほうが見やすいです。

一応自分が作ったrepositoryのcloneをdownloadします。

そしてrootDirectoryからfolderとfileを作りましょう 。"github/workflows/github-action.yml"

本人のfileに以下のコードをコピーペーストします。  

これが今後のschedulerとして本人のBlogLinkなどをもたらす仕組みです。

```typescript
# workflowの名前
name: GitHub Actions For My Profile
# どんな時に実行するのか
on:
  push:
    branches:
      - master
  # 一日1回cronする
  schedule:
    - cron: "0 0 * * *"

#workflow が実行する単位
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

## **Schedulerで実行されるreadmeUpdate.jsを作る**

vscondeのconsoleでnpm initをしてください。

```typescript
npm init -y
npm i rss-parser
```

そしてつくられったpakage.jsonのscriptsの中にいるtestをstartに変更します。

```typescript
"scripts": {
    "start": "node readmeUpdate.js"
  },
```

readmeUpdate.jsというfileを作ります。このfileがreadmeを作ります。

schedulerがこれを実行します。

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/197/img_2.webp)

```typescript
import { writeFileSync } from "node:fs";
import Parser from "rss-parser";

//自分のblogLink
const blogLink = ` https://yeolceo.tistory.com/rss`;

/**
 * README.MDとなるtext
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
  // rss-parserをつくります。それでfeedを持ってきます。
  const parser = new Parser({
    headers: {
      Accept: "application/rss+xml, application/xml, text/xml; q=0.1",
    },
  });
  const feed = await parser.parseURL(blogLink);

  // 債権のtitle, linkを持ってきます。そしてtextに追加
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
지금가지 개발한 스택 보여주는용
<a href="https://github.com/ten-log">
  <img align="center" src="https://github-readme-stats-theta-gules-17.vercel.app/api/top-langs?username=ten-log&layout=compact&theme=dark" />
</a>
<br /> */
```

このように情報さえあれば、githubのreadmeで整理して管理することができます。

参考

[https://docs.github.com/ko/actions/quickstart](https://docs.github.com/ko/actions/quickstart)

[https://yueliang-front-end.tistory.com/9](https://yueliang-front-end.tistory.com/9)
