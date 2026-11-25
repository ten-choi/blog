---
title: "Getting Started with Koa for Node.js"
labels: ["TS","JS","nodejs","KOA","koa.js","Archive"]
published: true
date: 2020-07-07T15:24:14+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 29
tistoryUrl: "https://yeolceo.tistory.com/29"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["KOA","koa.js","node.js"]
tistoryPostedAt: "2020-07-07 15:24:14"
language: en
bloggerPostId: "6402030765922790388"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/29/img.webp)

In short, Koa is a web framework for running servers on Node.js, like Express.

It was built by the people behind Express, and its main selling points are being lightweight and having first-class support for async code.

I'll explain as I go. (Honestly, I didn't notice a huge difference.)

## \- Initial Setup

Run yarn init -y in whatever folder you want to use.

Install the framework with yarn add koa.

[https://www.npmjs.com/package/koa](https://www.npmjs.com/package/koa)

Create a src folder and an index.js file inside it.

```html
const Koa = require('koa');

const app = new Koa();

app.use(ctx =>{              // ctx is short for context; it holds the web request and response info.
  ctx.body='hello world';    // Think of ctx as req and res rolled into one.
});							// Where Express uses app.use((req,res)=>{}), Koa uses a single ctx.

app.listen(4000, ()=>{
  console.log('Listening to port 4000');
});
```

In a command prompt, run node src from your project folder.

Type localhost:4000 into the address bar and hit Enter.

If you see hello world on the screen, the basics are done.

## \- next() Returns a Promise

In Koa, next() returns a promise. First-class async support is one of its big features.

```html
const Koa = require('koa');
const app = new Koa();

 ///////////////////// This is where the async part happens.
app.use((ctx,next)=>{

  console.log(1);
  console.log(ctx.url);
  if(ctx.query.authorized !== '1'){
    ctx.status=401;
    return;
  }
  next().then(()=>{     // END runs after the next middleware finishes.
    console.log('END');
  });
});
////////////////////////////////
app.use((ctx,next)=>{
console.log(2);
next();
});

app.use(ctx =>{
  ctx.body = "hello world";
});

app.listen(4000, ()=>{
  console.log('Listening to port 4000');
});
```

When the query value on localhost:4000 isn't 1, we set status=401 so the page shows as Unauthorized.

You can see the difference by comparing [http://localhost:4000/?authorized=1](http://localhost:4000/?authorized=1) with [http://localhost:4000](http://localhost:4000/?authorized=1).

If you already know Express, this should be easy to follow.

 You can also handle the async part above with async/await.

```html
Handling the async part above
app.use(async(ctx,next)=>{

  console.log(1);
  console.log(ctx.url);
  if(ctx.query.authorized !== '1'){
    ctx.status=401;
    return;
  }
    await next();
    console.log('END');
});
```

## \- Using koa-router

[https://www.npmjs.com/package/koa-router](https://www.npmjs.com/package/koa-router)

Add Koa's router with yarn add koa-router.

```html
const Koa = require('koa');
const Router = require ('koa-router'); // Router

const app = new Koa();
const router = new Router(); // Set up the router

router.get('/', ctx =>{
  ctx.body= 'index page (home)';
});

router.get('/blue', ctx =>{
  ctx.body= 'blue blue';
});
router.get('/red', ctx =>{
  ctx.body= 'red red';
});

app.use(router.routes());  // Apply the routes we defined.

app.listen(4000, ()=>{
  console.log('Listening to port 4000');
});
```

Create a default page plus blue and red pages, then start the Koa server.

If it looks like this, it worked.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/29/img_1.webp)

That's a very, very simple web router done.

Now let's modularize it. This is simple too.

Let's start with the code.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/29/img_2.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/29/img_3.webp)

[Line 12 can also just be app.use(router.routes());](http://app.use\(router.routes\(\)\);) However, if a REST method like POST or GET isn't handled,

you need allowedMethods to avoid errors, and then an 'allowedMethods' message is returned.

\- REST APIs use different HTTP methods depending on the kind of request. (The REST methods are listed below.)

\[   get: used to read data. | post: used to create data or authenticate. | delete: used to delete data.

             put: used to replace data entirely. | patch: used to update specific fields of data.   \]

We add the imported module's api.routes to the router on the index page. That makes the paths from the api module

available on the router, and then we apply the router's routes to the app with use.

This way, when you have tons of routes under something like api, you can split them up.

I've tried to go over Koa's features as simply as possible. I hope this helps.
