---
title: "Super Simple! How to Make a CentOS Bootable USB"
labels: ["OS","Linux","centos","Archive"]
published: true
date: 2020-12-22T11:15:15+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 62
tistoryUrl: "https://yeolceo.tistory.com/62"
tistoryCategory: "OS/Linux"
tistoryTags: ["centos","centos","centos","centos"]
tistoryPostedAt: "2020-12-22 11:15:15"
language: en
bloggerPostId: "7044233460346142758"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img-png.webp)

This post walks through making a CentOS bootable USB.

That said, if you download an Ubuntu ISO instead, the process of making the bootable USB is exactly the same.

### **\- Download the CentOS 7 ISO**

Go to the link below and click the ISO download link under the **green line**.

The green line means you should use the ISO images from that mirror site.

[isoredirect.centos.org/centos/7/isos/x86\_64/](http://isoredirect.centos.org/centos/7/isos/x86_64/)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_1-png.webp)

It doesn't really matter which line you click. (I went with Kakao — big company, after all...)

Click the **file in the pink box** as shown below, and the download will start.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_2-png.webp)

While the download is in progress, move on to the next step.

### **\- Making the Bootable USB**

The **CentOS 7** file you downloaded above should be about 4.4GB. Grab a USB drive of 8GB or more to be safe.

Next, download **Rufus**, a **bootable USB creation tool**. This is today's key point!

 Let's download **Rufus**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_3.webp)

Take a look at the official site and click the pink box below!!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_4.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_5.webp)

Once the download finishes, you should have the exe file shown above.

Run it right away. (If the ISO file hasn't finished downloading yet, stop here and wait.)

1\. Select your USB drive.

2\. Select the CentOS 7 ISO file you downloaded.

3\. Set the USB volume label.

4\. Choose FAT32 or Large FAT32; if neither is available, leave it at the default.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_6.webp)

Once everything is set, click Start.

![Select "Write in ISO Image mode (Recommended)"](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img.webp)

![The prompt asking whether to format the drive](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_1.webp)

That's all the setup. Now just wait for it to finish.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_2.webp)

Congratulations — your CentOS bootable USB is done.

When you actually use it, I recommend plugging it into a USB 2.0 port on a desktop. Happy coding!
