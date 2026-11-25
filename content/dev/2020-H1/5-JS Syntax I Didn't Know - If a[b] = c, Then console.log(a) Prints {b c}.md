---
title: "JS Syntax I Didn't Know: If a[b] = \"c\", Then console.log(a) Prints {b:\"c\"}"
labels: ["TS","JS","react","ES6","Archive"]
published: true
date: 2020-05-21T16:42:07+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 5
tistoryUrl: "https://yeolceo.tistory.com/5"
tistoryCategory: "TS, JS/react"
tistoryTags: ["JS","ES6","js","es6"]
tistoryPostedAt: "2020-05-21 16:42:07"
language: en
bloggerPostId: "5837244889589580121"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/5/img.webp)

#### **\- Error Screenshot**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/5/img_1.webp)

This seems to be JSX-style syntax, but it's the first time I've seen it written this way, so I'm writing it down.

If you use one variable as a bracket key on another object and assign a string, you get a JSON-like object as output. You can also pass nextState straight into setState.

You see this pattern fairly often for quickly building and using JSON-shaped objects.

```html
let userName="test";
let nextState={}
nextState[userName] = "value";
console.log(nextState);

//result: {test: 'value'}
```
