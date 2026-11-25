---
title: "Really Easy! Using RTSP in React, Part 2"
labels: ["TS","JS","react","rtsp","Archive"]
published: true
date: 2021-01-04T15:15:10+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 71
tistoryUrl: "https://yeolceo.tistory.com/71"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react","react","rtsp"]
tistoryPostedAt: "2021-01-04 15:15:10"
language: en
bloggerPostId: "2734495861273184845"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img.webp)

\- This post is based on the RTSP technology from the Streamedian site. It's a good fit for anyone developing RTSP on Windows;

for production work, you may need to buy a license or study how to run it in a Linux environment.

#### **\- Preparing the Projects**

We need to get **RTSP** running inside a **React** project, right?

Get the **Streamedian project** we used in **\[Really Easy! Using RTSP in React, Part 1\]** ready.

Then create a new project with **npx create-react-app \[project-name\]**.

Let's take a look at the **Streamedian** project!

We need to move the files involved in running **RTSP** from this project into the **React** project. free.player.1.8.4.js contains the code that makes **RTSP** possible over socket communication.

So copy **[free.player.1.8.4.js](http://free.player.1.8.4.js)** from the **RTSP project** and paste it into the **public** folder of the **React project**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_1.webp)

Once you've moved **[free.player.1.8.4.js](http://free.player.1.8.4.js)**, we need to use it, right? In **index.html**, add code that loads

that JavaScript file.  ->  Open **index.html**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_2.webp)

Referring to the code below, just slot it in between the **<head>** tags like this.

```html
<head>

    <script src="free.player.1.8.4.js"></script> // just add this line

  </head>
```

Now that we've moved the code that provides the **RTSP** functionality, we need to move the part that runs it, right?

Create a folder named **Streamedian** under the src folder of the **React project**.

The files below are the components responsible for running it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_3.webp)

They're the ones underlined in red in the **RTSP** project. (Feel free to move the CSS too if you want to tweak it.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_4.webp)

That's it for moving files!!! You're already halfway there — keep going!

#### **\- Modifying the React Project**

Take a look at the **Streamedian** folder in the **React project**. **[StreamedianPlayer.jsx](http://StreamedianPlayer.jsx)** is a component that mixes the video playback part with other parts.

Boldly remove whatever you don't use. Just keep the **video**, like below.

```html
render() {
    return (
      <div>
        <video id={this.props.id} controls autoPlay>
          {this.props.children}
        </video>
      </div>
    );
  }
```

And if you're not using something, you should remove its **import** too, right? Keep only the **React** import.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_5.webp)

We have **[free.player.1.8.4.js](http://free.player.1.8.4.js)**, which provides the **RTSP** functionality, and the **Streamedian** folder, the **player** that plays the video.

So all that's left is to call it from the **App.js** component..? Let's look at **index**, the entry point we'll call in **Streamedian**.

Edit the **index** file like mine. I've kept only what's needed.

```html
import React from 'react';
import StreamedianPlayer from './StreamedianPlayer';
// import './index.css';

const App = ({url, id}) => (
	<div>
		<StreamedianPlayer id={id} >
			{ <source  src={url} type="application/x-rtsp" /> }
		</StreamedianPlayer>
	</div>
);

export default App;
```

The **id** and the **RTSP** **url** are the key pieces for playing the video, so you must use them.

I passed them as props so they're easy to use from any component. That way you can call it simply as <Streamedian id={} url={} />.

**Now everything is ready**. Clean up the **App.js** file in **React**.

```html
import './App.css';

const App=()=>{
  return (
    <div className="App" >

    </div>
  );
}

export default App;
```

Then call **Streamedian** using the path of the folder we created (when you import a folder path, it loads that folder's index.js). And of course, pass the **id** and **url** along with it!

```html
import './App.css';
import Streamedian from './Streamedian';

const App=()=>{
  return (
    <div className="App" >

      <Streamedian id="test" url="rtsp://your-rtsp-url" />
    </div>
  );
}

export default App;

(Sorry — the RTSP stream I used here isn't mine, so I can't share it.)
```

Did your **RTSP** stream play?

![I blurred some parts since I'd rather not show everything....](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_6.webp)

For more accurate information, check the **official site**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_7.webp)

I hope this was quick and easy to follow. Happy coding!
