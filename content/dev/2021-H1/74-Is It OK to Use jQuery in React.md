---
title: "Is It OK to Use jQuery in React?"
labels: ["react","npm","Archive"]
published: true
date: 2021-01-10T12:15:16+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 74
tistoryUrl: "https://yeolceo.tistory.com/74"
tistoryCategory: ""
tistoryTags: ["react","react","npm","react"]
tistoryPostedAt: "2021-01-10 12:15:16"
language: en
bloggerPostId: "7808598192268833316"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/74/img-png.webp)

If you've used **JSP** and **jQuery** and then move to React, you might reach for jQuery out of habit, like I did.

#### **How It Started**

While working in **React**, I hit a point where I needed a mouse event.

It was **mouseup**, and I suddenly remembered using it in **jQuery** before.

I looked up how to use **jQuery** in **React** and applied **mousedown** and **mouseup** in **React**.

Later, I came across posts saying that **React** doesn't like you modifying the **DOM** directly.

(jQuery modifies the document directly, bypassing React.)

As I dug through docs, I also found posts comparing the performance of **Vanilla JS** and **jQuery**.

Even the developer who created **jQuery** said on Twitter that **jQuery** can't replace **JS**.

#### **Conclusion**

It's better not to use **jQuery** in **React**. As I kept looking, I also found that **HTML** supports **mouseup** natively. The official **w3schools** site has the **onmouseup Event**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/74/img_1-png.webp)

So I figured **React** would have it too, used the same search pattern, and added **React** to it.

It's all explained in the official docs. Whatever it is, follow the manual.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/74/img_2.webp)

Let's use things the way the manual says. Let's not build bizarre transforming robots.....

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/74/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/74/img_1.webp)
