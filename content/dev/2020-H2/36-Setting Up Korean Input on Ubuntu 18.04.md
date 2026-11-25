---
title: "Setting Up Korean Input on Ubuntu 18.04"
labels: ["OS","Linux","ubuntu","Archive"]
published: true
date: 2020-07-20T16:10:21+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 36
tistoryUrl: "https://yeolceo.tistory.com/36"
tistoryCategory: "OS/Linux"
tistoryTags: ["ubuntu","ubuntu","ubuntu"]
tistoryPostedAt: "2020-07-20 16:10:21"
language: en
bloggerPostId: "4658618070456139267"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img.webp)

## \- Setting Up Korean Typing on Ubuntu

This time, let's get Korean (Hangul) input working on Ubuntu.

A fresh Ubuntu install doesn't come with Korean input set up.

First, start Ubuntu in VMware.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_1.webp)

Click the 3x3 grid icon in the bottom-left corner.

You'll see a screen like the one above. Then open the app labeled Language Support.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_2.webp)

Enter the admin password you set for Ubuntu.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_12.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_13.webp)

Click Install / Remove Languages, select Korean, and click Apply. Follow the screens above  
and let it download.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_3.webp)

Not sure if it was just me, but the download took about an hour and a half...

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_4.webp)

Normally it just downloads and you're set, but some people say it doesn't show up afterward, and that happened to me too.

If it shows up on the first try, skip ahead. (If it didn't, just download it again. Nothing else is different.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_5.webp)

In the terminal, enter this command -> ibus-setup

A window like this will pop up.

I already have Korean added, but you probably won't. Use the Add button to find Korean.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_6.webp)

Once you find it, add it. Almost there.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_7.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_8.webp)

With that set, you need to configure the key that switches to Korean input.

Click the icon shown on the left and go into Settings.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_9.webp)

Follow the menu marked in red above and you'll reach a settings window like this one.

If you don't see Korean, click the + button and add it.

Then click the setting marked with a star to bring up the screen below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_10.webp)

In my case, it's Shift+Space. If yours is the same, click OK to close it; if not,

enter whatever shortcut you'd like.

Congrats! That's everything.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/36/img_11.webp)

I typed Korean in the terminal using that shortcut. That's a quick guide to setting up Korean input.

Thanks for reading!
