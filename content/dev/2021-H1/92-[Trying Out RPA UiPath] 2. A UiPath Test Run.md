---
title: "[Trying Out RPA UiPath] 2. A UiPath Test Run"
labels: ["ETC","RPA","UiPath","Archive"]
published: true
date: 2021-04-21T16:01:04+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 92
tistoryUrl: "https://yeolceo.tistory.com/92"
tistoryCategory: "ETC/RPA"
tistoryTags: ["UiPath","uipath","rpa","rpa"]
tistoryPostedAt: "2021-04-21 16:01:04"
language: en
bloggerPostId: "2271410391276055489"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img-webp.webp)

### UiPath Test Project

This time we'll use **UiPath** to **record and replay** what a user does when googling something in Chrome.

Let's go all the way to running it.

#### 1. Setting Up the Project

Create a new project.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img.webp)

I'll name the project **googleSearch**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_1.webp)

We'll be using **UiPath** features in the Chrome browser.

To do that, you need to install the UiPath extension in Chrome.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_2.webp)

Heads-up: you'll need to close all your Chrome windows once.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_3.webp)

Once it's **installed**, set it so it can **run on all sites**, as shown below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_4.webp)

If you hadn't installed the extension, you would have run into an error like this!!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_5.webp)

Okay, we're halfway done. Almost there!

### 2. Building a Simple Project

Go to the Start category and look under recently created items! Click googleSearch, which we made earlier, to open it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_6.webp)

We're finally inside the project.

We'll use two features this time: **Recording in the top bar** and **Debug File**.

****Click** the **Recording** button**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_7.webp)

Choose either Desktop or Web. Desktop would work too, but since we'll be using

a web browser, choose Web.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_8.webp)

A **recording** **window** like the one below appears. Hover over things and it kindly explains them, so take a look.

(Have the Google home page open before you start)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_9.webp)

Click the **Record button** and your mouse cursor changes. Hover over the search box and **click** it.

![](https://blog.kakaocdn.net/dn/msUXw/btq21MeojhC/uvXcWaM7N5oqMXo2kdMn0k/img.png)

You'll then be asked to **enter the value you want**, as below. I typed the Korean word for **"search"** and pressed **Enter**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_10.webp)

Once you press Enter, the **input** **recording** is done.

When it's back in a state ready for the next **recording**, move the mouse down and click **"Google Search"**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_11.webp)

If you land on a screen like the one below, click the **Save & Exit** button.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_12.webp)

It asks you to create a new sequence. **Click Create**. In my case I kept the default name.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_13.webp)

When it's done, the **process you just went through** shows up in UiPath Studio like a **flowchart**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_14.webp)

Now for the big moment: **running it**. Hoping you've followed along well, click the **Debug File** button!!

(The Google home page needs to be open, just like when you recorded it.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_15.webp)

Did it follow the sequence for you like it did for me?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_16.webp)

Have you got the basic idea of **RPA UiPath** now? If so, congratulations.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/92/img_17.webp)

If I write a follow-up, it'll be about using activities. Thanks.
