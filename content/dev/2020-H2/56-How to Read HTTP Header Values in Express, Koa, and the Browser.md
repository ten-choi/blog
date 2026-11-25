---
title: "How to Read HTTP Header Values in Express, Koa, and the Browser"
labels: ["JS","nodejs","express","koa","Archive"]
published: true
date: 2020-10-21T17:28:08+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 56
tistoryUrl: "https://yeolceo.tistory.com/56"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2020-10-21 17:28:08"
language: en
bloggerPostId: "419517036340166127"
---
Every HTTP request and response carries headers: `Content-Type`, `Authorization`, `User-Agent`, custom ones like `X-Request-Id`, and so on.
Here's how to read them in the places I use most: Express, Koa, and the browser.

## One Thing to Know First

Header names are **case-insensitive**.
Node.js stores incoming header names in **lowercase**, so `Content-Type` becomes `content-type`.
If you read the raw headers object, always use lowercase keys.

## Express

```js
const express = require('express');
const app = express();

app.get('/', (req, res) => {
  // 1. All headers as an object (keys are lowercase)
  console.log(req.headers);

  // 2. A single header from the object
  const userAgent = req.headers['user-agent'];

  // 3. req.get() / req.header() - case-insensitive
  const token = req.get('Authorization');
  const requestId = req.header('X-Request-Id');

  res.json({ userAgent, token, requestId });
});

app.listen(3000);
```

`req.get()` is the cleanest option. You can pass the name in any case.

To set a response header, use `res.set()`:

```js
res.set('X-Powered-By', 'my-server');
```

## Koa

```js
const Koa = require('koa');
const app = new Koa();

app.use(async (ctx) => {
  // All headers (same as ctx.request.headers)
  console.log(ctx.headers);

  // A single header - case-insensitive
  const token = ctx.get('Authorization');

  // Set a response header
  ctx.set('X-Powered-By', 'my-server');

  ctx.body = { token };
});

app.listen(3000);
```

## Browser (fetch)

On the client side, you read **response** headers with `response.headers.get()`:

```js
const res = await fetch('/api/users');

console.log(res.headers.get('Content-Type'));
console.log(res.headers.get('X-Total-Count'));

// Loop through all of them
for (const [key, value] of res.headers) {
  console.log(key, value);
}
```

## Why Is My Custom Header `null`?

If the request is cross-origin, the browser only exposes a few basic headers (`Content-Type`, `Cache-Control`, etc.) by default.
To read a custom header like `X-Total-Count`, the server has to allow it explicitly:

```js
// Express
res.set('Access-Control-Expose-Headers', 'X-Total-Count');
```

If you use the `cors` package, you can set it once:

```js
const cors = require('cors');
app.use(cors({ exposedHeaders: ['X-Total-Count'] }));
```

## Quick Test with curl

```bash
# Send a custom header
curl -H "X-Request-Id: abc123" http://localhost:3000

# Show the response headers too
curl -i http://localhost:3000
```

## Summary

| Where | Read | Set |
|---|---|---|
| Express | `req.get('Name')`, `req.headers['name']` | `res.set('Name', value)` |
| Koa | `ctx.get('Name')`, `ctx.headers['name']` | `ctx.set('Name', value)` |
| Browser | `res.headers.get('Name')` | `fetch(url, { headers: { ... } })` |

Remember: lowercase keys for the raw object, and `Access-Control-Expose-Headers` for custom headers across origins.
