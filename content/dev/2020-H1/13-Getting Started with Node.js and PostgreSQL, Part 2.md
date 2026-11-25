---
title: "Getting Started with Node.js and PostgreSQL, Part 2"
labels: ["DB","rdb","PostgreSQL","node.js","react","Archive"]
published: true
date: 2020-05-26T16:36:57+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 13
tistoryUrl: "https://yeolceo.tistory.com/13"
tistoryCategory: "DB/rdb"
tistoryTags: ["PostgreSQL","node.js","node.js","react"]
tistoryPostedAt: "2020-05-26 16:36:57"
language: en
bloggerPostId: "6759923018362356063"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img.webp)

**First, open the cmd Command Prompt.**

Navigate to the folder you want to use. Mine is called pg-test.

Run npm init. (If you don't have Node.js, you'll need to download it.) https://nodejs.org/ko/

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img_1.webp)

I set the package name to pg-test for consistency.

description is just a short description of the project. I'm practicing pg so I can post about it on Tistory, so I set it like that.

author is optional. Fill it in if you want.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img_2.webp)

Press Enter through the rest and you're done.

You should now have a package.json file in your folder. We've finished the very basic skeleton.

Next, we need to set up dependencies. Dependencies are the modules our project absolutely needs in order to run,

and they're listed under "dependencies".

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img_3.webp)

**Now that we have the skeleton, let's tell Node what environment we'll run with.**

**It's important to know what you're using.**

  "dependencies":{  
    "body-parser": "\*",  
       "dust": "\*",  
       "dustjs-helpers": "\*",  
       "dustjs-linkedin": "\*",  
       "express": "\*",  
       "pg": "\*",  
       "pg-pool": "^3.2.1",

       "consolidate": "\*"  
  }

**1. body-parser is middleware that lets you read the request parameters of a POST request.**

//Parse incoming request bodies with body-parser.

app.use(bodyParser.urlencoded({extended:false });

This is the urlencoded option. If extended is false, it uses Node.js's built-in querystring module;

if it's true, it uses the npm qs library.  querystring = URL query string

Requests are usually sent with GET or POST, and the two parse parameters differently.

If the client submits (sends some data) with POST,

the server can read it as a param when it handles (receives) the request.

So if the client has <input name ={'id'} /> and submits it via POST,

the server can read it as let id = req.param('id'));

**2. dust is a template engine that makes writing HTML easier. The other dust packages are for templating too.**

**3\. express is middleware built for web servers and runs on top of the HTTP module.**

   Put simply, it's a framework used as middleware in Node.js that makes running a server easy.

const express \= require("express");

const app \= express();

const PORT \= 3000;  

app.listen(PORT);  These 4 lines alone are enough to run a server.

**4\. pg and pg-pool are modules for using a PostgreSQL database.**

**5. consolidate is a library that unifies template engines. We use it for the dust templates.**

Hopefully you now understand what we're depending on. Next, run npm install

to download the modules we declared as dependencies.

I created app.js myself. When setting up the package, I specified app.js as main.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img_4.webp)

Now let's do the basic setup.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img_5.webp)

This means we're implementing a web server with express that listens on port 3000.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/13/img_6.webp)

Run it and the console log should print. If you open [http://localhost:3000/](http://localhost:3000/) and get a Cannot GET / error,

you've successfully created the server. Congrats!

In the next post, I'll show you how to use PostgreSQL.
