---
title: "A Quick Hands-On with Node.js and PostgreSQL, Part 3"
labels: ["DB","rdb","PostgreSQL","node.js","Archive"]
published: true
date: 2020-06-05T15:31:03+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 16
tistoryUrl: "https://yeolceo.tistory.com/16"
tistoryCategory: "DB/rdb"
tistoryTags: ["PostgreSQL","node.js","postgresql"]
tistoryPostedAt: "2020-06-05 15:31:03"
language: en
bloggerPostId: "5047958850908428118"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/16/img.webp)

I've tweaked the `require` statements from Part 2 a little.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/16/img_1.webp)

I'll stick to the bare minimum of `require`s here.

One thing I didn't cover before is `cors`. You need it because the server throws a CORS error when it sends values back.

Browsers block data coming from another origin for security reasons, so we fix that by installing a library.

[npm cors](https://www.npmjs.com/package/cors)

That's everything we need to add.

const config = {  
  user: 'username',  
  password:' password ',  
  host: 'localhost',  
  port: 5432,  
  database: 'database name',  
};  
let pool = new Pool(config);

"Config" stands for configuration. This is where you put your database settings.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/16/img_2.webp)

body-parser is there to read POST data.

If you're only running things inside Node.js, you might not need body-parser or cors.

But they come in handy once you start using POST and wiring up the DB, server, and client, so I recommend looking into them.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/16/img_3.webp)

My table is called `usertable`, and I'm only selecting the username.

If you add a user and then open local port 3000 at [http://localhost:3000/](http://localhost:3000/), the values you queried

will be printed by Node.js.

Step by step: we call `get` on the Express app, using the path given as the first parameter.

Below that, we `connect` using the DB settings we entered earlier,

and if that `then` passes, we run the query. If the query succeeds, we close the connection

and `send` the result, so the values of `result.rows` show up as JSON at the path we chose.

If you've built a separate client page running on a different port, cors takes care of the security issue.

Thanks for reading!
