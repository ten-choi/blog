---
title: "Learning Ant Design with React (Dashboard), Part 1"
labels: ["TS","JS","react","frontend","antdesign","Archive"]
published: true
date: 2020-05-25T15:02:08+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 8
tistoryUrl: "https://yeolceo.tistory.com/8"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","frontend","antdesign"]
tistoryPostedAt: "2020-05-25 15:02:08"
language: en
bloggerPostId: "6871569175653977316"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/8/ant.webp)

**If you landed here by searching for Ant Design, I'm guessing you already have some understanding of frontend development.**

(If not, I'll walk through things step by step starting with the next post!!)

Put simply, Ant is a library that makes it easy to design your product's views.

If you've used Bootstrap, it works in a similar way.

The difference is that it supports Angular, Vue, and React.

**How to Use It**

If you've installed the npm package for creating React apps with npm install -g react-create-app,

you then need to run npx create-react-app in the Command Prompt.

**\- The Difference Between npx and npm**

    As you know, npm is Node's package manager and helps you install the modules you need.

    Starting with npm 5.2, though, it ships with a built-in package called npx. npm saves modules to a local folder and runs them from there.

    But if you mix global and local packages, version management gets painful. npx was made to solve this:

    instead of saving the module, it fetches the latest version and runs it. In other words, it's an npm tool that fixes the versioning problem.

Set up your React app.

After that, using Ant is very simple.

[https://ant.design/](https://ant.design/)

Go to the URL and open Components.

Then pick the component you need for the view you want from the left sidebar.

[https://ant.design/components/layout/](https://ant.design/components/layout/)

For example, if you open Layout, you'll see images of different layouts.

Click "show code" below one and you'll see the code for how it's built.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/8/캡처.webp)

Just grab the look you want and use it like this.

That's a quick overview. Most of the code is documented, but it's in English, so if that's hard for you,

I recommend using Chrome's built-in translation.

**In the next post, we'll build a simple button with Ant.**
