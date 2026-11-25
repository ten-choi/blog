---
title: "Learning Ant Design with React (Dashboard), Part 4"
labels: ["TS","JS","react","frontend","antdesign","Archive"]
published: true
date: 2020-05-26T10:47:35+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 11
tistoryUrl: "https://yeolceo.tistory.com/11"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","frontend","antdesign"]
tistoryPostedAt: "2020-05-26 10:47:35"
language: en
bloggerPostId: "7574206615211157201"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/ant.webp)

**This time, we'll finish setting up the layout, everything except the sidebar.**

We'll code the screen based on the code from the Layout component.

The layout breaks down into the Header (top menu), Sider (side menu), Content (main area), and Footer (whatever goes at the bottom).

**It's more efficient to divide up your sections from the start.**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/1.webp)

For styling, look at the Sider: you can add a color like that. I set it to red to make it stand out.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/2.webp)

If you look at the screen, the text is hard to read and small. So let's go change the font size.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/3.webp)

We'll use Title, where the level sets the size. Grab whichever one you like and put it inside the Header. Don't forget the import.

(If you have multiple imports from 'antd', combining them like import { Layout , Typography} from 'antd'; keeps things clean.)

If the text is still hard to read, set its color to white via style and the title will stand out.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/4.webp)

If app.css centers the text, change it to left. Dashboards usually have the name in the top-left corner.

Next, we'll set up the user's avatar. We'll place it in the top-right so it looks like the logged-in user.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/5.webp)

Grab the Avatar component. You pass an image path via src, but I didn't have an image for the avatar.

So use any image you like, or grab one from the link below, or use the images I've uploaded.

[https://icon-icons.com/](https://icon-icons.com/)

You can pick an icon you like from a site like this, or use the icons I uploaded.

Put the images in the public folder. (That's how React lets you reference an image src directly.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/user-icon-test1.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/logo192.webp)

If you then add an icon next to the title as well, your code will end up like this.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/3_1.webp)

If things aren't lined up, adjust the spacing with padding. The text is already left-aligned in app.css, so use float

to position the Avatar.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/2_1.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/blob.webp)

The header looks nice now. But it doesn't quite look like a dashboard yet.

The middle is too empty. So let's fill it in.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/11.webp)

Go back to Layout and copy the Content section. Follow the scrollbar down and click </> to see code like the above.

For the parts that were styled with CSS, though, put those values directly on the div as inline styles.

Don't forget the imports.

Breadcrumb is the menu above the content, and the div inside it marks where the main content goes.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/1_1.webp)

That's looking pretty close to a dashboard. I hope yours does too. Here's the current code.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/11/1_2.webp)

Ant is honestly amazing for letting you build a view like this in so little time.

Even if it's not Ant, getting in the habit of using something that cuts down the time you spend on views really helps.

Next time, we'll build a menu in the sidebar. Thanks!
