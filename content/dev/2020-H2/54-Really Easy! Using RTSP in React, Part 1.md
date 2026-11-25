---
title: "Really Easy! Using RTSP in React, Part 1"
labels: ["TS","JS","react","rtsp","streamdian","Archive"]
published: true
date: 2020-10-20T17:07:10+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 54
tistoryUrl: "https://yeolceo.tistory.com/54"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","rtsp","streamdian","react"]
tistoryPostedAt: "2020-10-20 17:07:10"
language: en
bloggerPostId: "8822024657025768002"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img.webp)

\-This post is based on the RTSP tech from the Streamedian site. It's a good fit if you're developing on Windows and want to try RTSP. 

For real-world work, you may need to buy a license or learn how to run it on Linux.

## **\-RTSP** 

**Real Time Streaming Protocol** is a protocol designed to control streaming servers in real time.

For example, protocols like RTSP or HLS are used when playing live video such as CCTV feeds.

## **\-Streamedian**

Streamedian is a video player that supports **RTSP streaming over WebSockets** to make developers' lives easier.

Search for it and head to the official site.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_1.webp)

First, let's get ready for socket communication.

The site's landing page should look like the screenshot below. Click the part underlined in red.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_2.webp)

There are several versions you can download. We want the **react** one, underlined below!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_3.webp)

Once the download finishes, you'll get an archive like the one below. Make a folder wherever you like and extract it there.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_4.webp)

After creating the folder and extracting the files, run `npm install` in that folder.

(This installs all the required libraries!)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_5.webp)

Did **npm install** finish installing the modules? Then let's run it with `npm start`!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_6.webp)

Did it start up successfully? You're already halfway there.

Once it's running, you'll see a screen like this.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_7.webp)

Enter the URL labeled "sample" and click "set" to play the video. 

If it doesn't play, that's totally expected. 

To use RTSP, Streamedian provides socket communication as a service, and we 

haven't installed it yet. Let's go install it!

## \-Installing the WebSocket Service

We're almost at the finish line. Hang in there!

This time, download the RTSP socket client underlined in red.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_8.webp)

Scroll down and pick your operating system. I chose Windows 10.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_9.webp)

Just keep clicking Next and the install finishes. Click away!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_10.webp)

Once it's installed, open Task Manager.

Do you see **streamedian proxy service** on the Services tab, like below?

Then you're all set! 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_11.webp)

\[The service sometimes stops. If that happens, right-click it in Task Manager and choose Start.\]

Now head back to the **react** app we started.

Put an **RTSP URL** in the input box and click "set", and the video for that URL will play.

(I found a sample URL to test with, but maybe the RTSP stream itself was broken... the video didn't play, though it did show that it's about 9 minutes long...)

If you have your own RTSP URL, you can try it right away.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_12.webp)

If you want to add RTSP to your own React app, check out **\[Really Easy! Using RTSP in React, Part 2\]**.

Hope this helped. Happy coding!
