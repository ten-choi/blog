---
title: "Making Async Calls Run Synchronously in Node.js (async-lock)"
labels: ["TS","JS","nodejs","restapi","async","async-lock","Archive"]
published: true
date: 2021-05-17T09:03:07+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 94
tistoryUrl: "https://yeolceo.tistory.com/94"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["비동기를","restapi","async","async-lock"]
tistoryPostedAt: "2021-05-17 09:03:07"
language: en
bloggerPostId: "3884363771094736382"
---
I ran into a strange situation where a device couldn't handle multiple requests at once, so I ended up trying this myself.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/94/img.webp)

It's a library that makes execution run synchronously.

For example, if you send two requests through a REST API, it finishes one before sending the next.

With it, tasks are processed one at a time, in order.
