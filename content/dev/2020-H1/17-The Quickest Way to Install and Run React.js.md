---
title: "The Quickest Way to Install and Run React.js"
labels: ["TS","JS","react","react.js","Archive"]
published: true
date: 2020-06-05T16:19:04+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 17
tistoryUrl: "https://yeolceo.tistory.com/17"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react.js","react"]
tistoryPostedAt: "2020-06-05 16:19:04"
language: en
bloggerPostId: "7013467649503521073"
---
I'm using Node.js, with Atom as my editor. (Any other IDE works just as well.)

Node.js® is a JavaScript runtime built on [Chrome's V8 JavaScript engine](https://v8.dev/).

In other words, it's an environment for JavaScript development.

Since React.js is also JavaScript, you'll need to download Node.js from [https://nodejs.org/ko/](https://nodejs.org/ko/).

npm is the package manager for JavaScript, and you can only use it once Node.js is installed.

Setting environment variables isn't required, but it makes life easier.

[https://yeolceo.tistory.com/category/node.js](https://yeolceo.tistory.com/category/node.js)

That post explains how to set up the environment variables.

Now let's create a React app. It's really simple.

[https://www.npmjs.com/package/create-react-app](https://www.npmjs.com/package/create-react-app)

If you're on the C drive, copy the path of the folder you want and, in cmd, run `C:\\user\\...> cd (your path)`.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/17/img.webp)

Type the command as shown and hit Enter. create-react-app is, as the name says, a library that creates a React app for you.

`i` is short for `install`. Enter `create-react-app (your project name)` and press Enter.

I created a project called `test`.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/17/img_1.webp)

If you're using Atom like me, go ahead and open it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/17/img_2.webp)

Click `app.js` in the `src` folder and you should see the same screen as mine.

Now it's time to run it.

Open the Command Prompt (cmd).

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/17/img_3.webp)

In your project folder, run `npm start`.

That's the command that runs React.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/17/img_4.webp)

Congratulations! If you see the same screen as mine, you're all set.

That's React, from install to running, in a single page.
