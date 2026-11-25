---
title: "How to Send Values from React to Express, Part 2"
labels: ["TS","JS","react","Archive"]
published: true
date: 2020-11-10T17:47:40+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 57
tistoryUrl: "https://yeolceo.tistory.com/57"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react"]
tistoryPostedAt: "2020-11-10 17:47:40"
language: en
bloggerPostId: "2921006054799736012"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_12.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_13.webp)

Just a quick explanation, and then we'll install React right away!

To send values from React to Express, you need to install two libraries in your React app.

They are **axios and http-proxy-middleware**.

## \-axios

To pass values from **React** to **Express** using GET or POST, you need a library, and that's **axios**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img.webp)

## \-http-proxy-middleware 

When you send values from React to Express through a REST API (e.g. passing values with GET or POST),

Node.js and React run on different ports. In that case, we install http-proxy-middleware

so the values can still get through even though the ports differ. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_1.webp)

## **\-Creating a React App with CRA**

That's it for the explanation. Shall we install React now?

I'll create a folder called client on my desktop and put the React app inside it. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_2.webp)

Then I ran the command below to create a React app named react-app.

npm create react-app react-app 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_3.webp)

Now run the React app we just created with `npm start` from that directory!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_4.webp)

Is your React app running on localhost:3000?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_5.webp)

This is the original code, the App.js component. Open it up.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_6.webp)

**Now delete everything inside it.** 

Remove all the unimportant parts and make it look like the code below. Click the button and check that the console log shows up!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_7.webp)

Too easy? You're already halfway done. 

It's a super simple snippet that logs to the console when you click!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_8.webp)

Ta-da! lol

Go back to the command prompt where react-app is running and install the two libraries.

**axios and http-proxy-middleware: these two are the key!**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_14.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_15.webp)

**Let's start with http-proxy-middleware.** 

**This is the proxy setup that lines up the Node.js port and path!**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_9.webp)

**Create a setupProxy file and write the following.**

```html
const { createProxyMiddleware } = require('http-proxy-middleware');  // import the middleware
module.exports = function(app) {

  app.use(createProxyMiddleware( '/api',{   // only match URLs that contain /api
      target: 'http://localhost:5050/',     // and forward them to this URL
      changeOrigin: true,    
      secure: false                         // no TLS verification
    })
  );
};
```

**option.changeOrigin**: true/false, Default: false - changes the origin of the host header to the target URL

This means it changes the header to the target URL. Simply put, if Node.js is using port 5050,

think of it as port 3000 borrowing port 5050's functionality. With that in place, hitting localhost:3000/api

returns a value, the same one Node.js outputs. (Easy to test if Node.js's /api route is a GET.)

If you look closely at the npm page, there are lots of explanations in *English*. Google Translate is the best translator...

Here's the final App component using axios. 

```html
import logo from './logo.svg';
import './App.css';
import axios from 'axios';   // add axios

const App=()=>{

  const send =()=>{
    const client = axios.create();   // create an axios instance
    const name = 'My name is Conan';   
    client.post('/api' , {name} );   // POST via axios, sending the name value
}

  return (
    <div className="App">
        <button onClick={ ()=>{ send(); }}>Send button!</button>
    </div>
  );
}

export default App;
```

Not much different from before, right? Click the button and...

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_10.webp)

Ta-da! This prompt is the Node.js one. (Both React and Node.js need to be running.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_11.webp)

Heh... my name is Conan, detective...

The value we received shows up nicely here. Did it work for you?

Once things settle down at work, I'll wrap up with Part 3: returning a value from Express and using it back in React.

If you followed along, nice work. Happy coding!
