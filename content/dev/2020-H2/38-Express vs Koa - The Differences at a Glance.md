---
title: "Express vs Koa - The Differences at a Glance"
labels: ["TS","JS","nodejs","koa","express","Archive"]
published: true
date: 2020-08-11T17:45:09+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 38
tistoryUrl: "https://yeolceo.tistory.com/38"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["koa","express","koa"]
tistoryPostedAt: "2020-08-11 17:45:09"
language: en
bloggerPostId: "1326351167688592951"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/38/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/38/img_1.webp)

## **\- Overview**

The two best-known web frameworks built on Node.js are

Express and Koa. Here's a look at how they differ.

## **\- Details**

### **. Express**

**\*Pros**

1\. Express comes with a lot built in.

   Because it has so many features, you can use them without any extra hassle.

For example, you can use something like app.get('/', (req, res)=>{ }); right away.

 -> Koa doesn't work that way. You have to add routing through npm before you can use it.

2\. It's well known and has been around for a long time.

  The amount of information out there is on a different level. Countless people have written about their Express problems and questions,

  and those posts are still around online, so answers are easy to find.

  Because it's so popular, Express alone can handle most Node.js server problems.

**\*Cons**

It ships with features even if you never use them, so you could call it a bit heavy.

When using async/await, you have to wrap things in try/catch. (Otherwise you get errors along with warnings.)

### **. Koa**

**\*Pros**

1\. It was built by the Express developers. (It has the pedigree.)

It only has the basic structure, and features are split out into modules. Being able to pull in just what you need, when you need it,

is a plus. Honestly, the difference probably isn't big, but I'd expect it to be more efficient in things like disk footprint when deploying a server

and execution speed.

2\. It's based on ES6, so you can use async/await without needing try/catch.

   It's a small thing, but stuff like that is convenient.

**\*Cons**

If you want a feature, you have to pull it in manually yourself, which can be inconvenient.

(For example, Express has a router out of the box, but with Koa you have to install one with npm or yarn.)

Searching for Koa help is also harder than for Express. (Personally, I feel there are fewer examples out there.)

Having used both, I found that the web framework was secondary anyway.

The time goes into building the server itself (assuming the learning curve is similar). But if it's your first time, I'd recommend Express.

There's a lot more information available. I've only covered the key points here. I hope this helps.
