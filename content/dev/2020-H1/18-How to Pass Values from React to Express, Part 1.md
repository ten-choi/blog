---
title: "How to Pass Values from React to Express, Part 1"
labels: ["TS","JS","react","express","Archive"]
published: true
date: 2020-06-05T17:01:03+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 18
tistoryUrl: "https://yeolceo.tistory.com/18"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","express"]
tistoryPostedAt: "2020-06-05 17:01:03"
language: en
bloggerPostId: "2401046973187607844"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img_5.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img_6.webp)

**If you need this post, I'll assume you already know the difference between React.js and Node.js.**

**I've reorganized this into Parts 1 and 2 and filled in what was missing from the earlier version. Part 3 is planned!**

**Part 1 covers Node.js and Part 2 covers React. If you already know Node.js, skip ahead to the link below.**

[www.yeolceo.com/57](https://www.yeolceo.com/57)

**Let's jump right in, starting with Node.js.**

Create a Node.js file wherever you like.

I made a folder on my desktop: Desktop -> server -> express.

Then I created a file called `index.js`. (I'm using Atom as my editor. VS Code is more popular, so go with that.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img.webp)

Once you've created `index.js` in that folder, enter the code below.

It's a minimal snippet that uses Express to run a server in Node.js.

```html
const express = require('express');  // Load Express, a framework for running a server
const app = express();        // Use Express
const port = 5050;            // Set the port number

app.get('/', (req, res)=>{                 // On a GET request to '/', send this
    res.send('Hiya, hello world, hahaha');
});

app.listen(port, ()=>{         // Start the server
  console.log(`http://localhost:${port}  is the address.`);
})
```

Once you've typed that in, open the Command Prompt. Search for "cmd" in Windows

and the Command Prompt will open. Then move to the folder you set up. Here's an example:

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img_1.webp)

#### Next, install Express, the framework that helps you run the server.

  (`--save` records Express in your package.json if one exists, but you can leave it out!)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img_2.webp)

Did the install go fine? If so, type `node index.js` in the Command Prompt and hit Enter.

Is it running?

Great! Now open your browser and go to localhost on port 5050 -> http://localhost:5050/

If you see the screen below, you've followed along correctly.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img_3.webp)

That completes the basic Node.js setup. Nicely done!

Now let's add a bit more functionality.

Run `npm i body-parser`. You need a parser to properly receive values sent via POST.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/18/img_4.webp)

The npm page has a more detailed explanation.

[www.npmjs.com/package/body-parser](http://www.npmjs.com/package/body-parser)

Great job, everyone, for following along this far.

#### **Shall we add body-parser and finish our code?**

```html
const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const port = 5050;

app.use(bodyParser.json());

app.post('/api', (req, res)=>{
  let name = req.body.name;
    console.log(name);
    console.log('Detective, right? ');
});

app.listen(port, ()=>{
  console.log(`http://localhost:${port}  is the address.`);
})
```

I think you can guess what value `name` will receive! lol

That wraps up the Node.js part, nice and simple. Before moving on to the React side,

it's a good idea to make sure the code above makes sense to you!

When you're ready, head over to the link below!

[www.yeolceo.com/57](https://www.yeolceo.com/57)
