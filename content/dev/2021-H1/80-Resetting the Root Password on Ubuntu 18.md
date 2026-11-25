---
title: "Resetting the Root Password on Ubuntu 18"
labels: ["OS","Linux","Ubuntu","ubuntu","Archive"]
published: true
date: 2021-02-01T14:50:05+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 80
tistoryUrl: "https://yeolceo.tistory.com/80"
tistoryCategory: "OS/Linux"
tistoryTags: ["우분투","우분투","우분투","우분투","ubuntu","ubuntu","ubuntu"]
tistoryPostedAt: "2021-02-01 14:50:05"
language: en
bloggerPostId: "1781435624473074856"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img.webp)

### **\-Linux**

When you use Linux and need to change and save important settings, you have to use the **root account**.

That's because important settings need a layer of **security**. So if you **lose the root password**,

you'll run into **restrictions** when using a lot of the key commands in Ubuntu.

You really shouldn't forget the root password. But we're **only human**, so we **forget** things.

That's why there's a way to **reset** and **change** the password.

Let's look at how to reset the password on Ubuntu 18.   \*From here on, I'll just call Ubuntu 18 **Ubuntu**

### **\-How to Reset the Password**

Start Ubuntu, or if it's already running, restart it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_1.webp)

While it's booting, hold down **Esc** or **Shift** and you'll get the screen below.

(Some people say to mash the key, but in my case holding it down worked fine)

1\. The first screen of the GRUB bootloader appears. Select the second option in the menu.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_2.webp)

2\. Next, select recovery mode.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_3.webp)

3\. To change the root password, select root from the menu.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_4.webp)

4\. That takes you to a screen where you can type.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_5.webp)

If you just pressed Enter here and it moved on, you can **fix** it with the commands below.

```html
$ mount -rw -o remount /
$ passwd root
```

Once the password is set via the command, you'll see the message **password updated successfully**,

and the password should be applied.

If it worked, shut down and boot back up, and the **root account** password will be **applied** just as you set it.

### **\-But... If It Didn't Work**

Being curious, I wanted to try changing the password one more time. Then I got **Give root password for maintenance**.

It's asking for the existing root password for maintenance.

But I'm doing this precisely because I don't know the password...

In that case, go back to normal once via resume, then bring up the menu again. Then press e.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_6.webp)

You'll see a screen like the image below. Scroll all the way down.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_7.webp)

On the line just above initrd, the one highlighted in red, add **rw init=/bin/bash**.

Once you've typed it at the end, after **quiet**, press **Ctrl + X** to **apply** it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_8.webp)

If you see the root account at the bottom like I do, you're on track. Use the **passwd** command to **reset** the password.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_9.webp)

Enter the **password** you want for the **root account**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_10.webp)

Once the password is set, reboot with the reboot -f command.

When you're back at the menu, wait or press Enter once on this screen.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_11.webp)

Press Enter once more and find the resume menu.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_12.webp)

If you made it to this screen, use resume to start again with a normal boot.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_13.webp)

Now everything's ready. Start Ubuntu and open a terminal.

To log in as root, type the **su** command and your **password**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_14.webp)

I hope it worked for you too. Nice work, and happy, diligent coding.
