---
title: "Super Simple! Using jQuery in React"
labels: ["TS","JS","react","Archive"]
published: true
date: 2020-12-30T17:34:51+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 66
tistoryUrl: "https://yeolceo.tistory.com/66"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react","react"]
tistoryPostedAt: "2020-12-30 17:34:51"
language: en
bloggerPostId: "1125016044972694493"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_7.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_8.webp)

**A really simple guide to using jQuery in React.**

### **1\. React Project Setup**

 If you have a React project lying around unused, go ahead and use it; if not, refer to the image below.

 Create a project with the npx create-react-app \[project-name\] command.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img.webp)

Once the project is created,

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_1.webp)

run the npm i jquery --save command.

This installs jQuery into the project.

(You can also find it by **searching "npm i jquery" on Google**.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_2.webp)

Got your project running too? Then let's open it in an editor.

(Everyone uses VS Code, but I tend to use Atom as well, heh...)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_3.webp)

**2\. Using It in a React Class Component**

With App.js open, clean it up like this:

```html
import './App.css';
import React from 'react';

class App extends React.Component {
  render(){
    return (
      <div className="App">

      </div>
    );
  }
}

export default App;
```

I'll show the class version first, then the function version.

Import the jQuery we added through npm, and wrap the jQuery code in componentDidMount() so it runs after rendering.

```html
import './App.css';
import React from 'react';
import $ from "jquery";

class App extends React.Component {

  componentDidMount() {
    $(".target").mousedown(function () {      // when the mouse button is pressed
      console.log('pressed');
    });
    $("button").mouseup(function () {       // when the mouse button is released
     console.log('released!');
    });
  }

  render(){
    return (
      <div className="App">
        <button className="target">Button</button>
      </div>
    );
  }
}

export default App;
```

The official docs explain why we use jQuery this way.

According to the docs, React isn't aware of changes made to the DOM outside of React, and it manages its own

updates. So to work with the DOM, we get a reference to the element we want to apply jQuery to

inside componentDidMount, the lifecycle method meant for DOM work.

Do you see output like this when you press and release the button?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_4.webp)

**3\. Using It in a React Function Component**

This time I'll show a version that uses hooks.

First, clean things up into a function component.

```html
import './App.css';

const App=()=>{
  return (
    <div className="App">

    </div>
  );
}

export default App;
```

Using useEffect and useState, the code below changes the displayed text when you press and release the button.

```html
import './App.css';
import {useEffect, useState} from 'react';
import $ from "jquery";

const App=()=>{

  const [text, setText] = useState('The year is over.');
  useEffect(()=>{
    $(".target").mousedown(function () {
      setText('One year older!')
    });
    $("button").mouseup(function () {
      setText('The year is over.')
    });

    console.log('changed');
  }, []);

  return (
    <div className="App">
      <button className="target">Button</button>
      <div>{text}</div>
    </div>
  );
}

export default App;
```

Does the display change like below when you click the button?

![Button pressed](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_5.webp)

\- Button pressed

![Button pressed and released](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_6.webp)

\- Button pressed and released

 That's a quick look at how to use jQuery. Beyond the setup, you use jQuery in React exactly the same way

 you would anywhere else. Nice work! Happy coding!
