---
title: "[ Typescript ] How to Debug TypeScript in VS Code"
labels: ["TS","JS","typescript","Debug","VSCode","Archive"]
published: true
date: 2022-05-11T16:46:23+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 131
tistoryUrl: "https://yeolceo.tistory.com/131"
tistoryCategory: "TS, JS/typescript"
tistoryTags: ["Debug","typescript","VSCode"]
tistoryPostedAt: "2022-05-11 16:46:23"
language: en
bloggerPostId: "3899491199059336938"
---
#### Environment

Mac m1, VScode, node 16

#### Overview

When you try to run the debugger with TypeScript, it often can't find modules, and doing it any other way takes a bit of fiddling.

## **\- VScode Debug Setting**

Don't bother running it internally—just run it from package.json.

First, create a script that starts the server.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/131/img.webp)



Then, in debug mode, run the debugger with the script you set up, as shown below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/131/img_1.webp)

Got stuck on something trivial for a while there, phew... Happy coding, and keep at it.
