---
title: "Uncaught SyntaxError: Unexpected token '<'"
labels: ["TS","JS","react","Uncaught","Archive"]
published: true
date: 2020-12-23T10:18:32+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 63
tistoryUrl: "https://yeolceo.tistory.com/63"
tistoryCategory: "TS, JS/react"
tistoryTags: ["Uncaught"]
tistoryPostedAt: "2020-12-23 10:18:32"
language: en
bloggerPostId: "3775347678913541048"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/63/img.webp)

I ran into this maddening error. In my case, it happened in React.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/63/img_1.webp)

Line 2 below threw the error above, and after some digging I found that adding line 1 fixes it.

```html
<head>
    <title>React App</title>
    <base href="/" />                               - Line 1 - the fix
    <script src="free.player.1.8.4.js"></script>    - Line 2 - the problematic script
  </head>

  <body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="root"></div>
  </body>
```

**\- What I Found**

<base href="URL" /> 

The base element sets the base URL for every relative URL on the page.

In my case, the app loaded different pages depending on the URL, and only one of those pages had this problem.

Even after deleting all of its internal code, I got the same result. None of the other React files had this issue.

In other words, it happens in specific cases: not on every URL, but on undefined URLs, where the base URL becomes the problem.
