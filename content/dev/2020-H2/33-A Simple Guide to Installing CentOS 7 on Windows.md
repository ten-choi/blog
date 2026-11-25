---
title: "A Simple Guide to Installing CentOS 7 on Windows"
labels: ["OS","Linux","centos7","vmware15.5","vmware","Archive"]
published: true
date: 2020-10-30T11:09:54+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 33
tistoryUrl: "https://yeolceo.tistory.com/33"
tistoryCategory: "OS/Linux"
tistoryTags: ["centos7","vmware15.5","vmware"]
tistoryPostedAt: "2020-10-30 11:09:54"
language: en
bloggerPostId: "533643286864064617"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img.webp)

## \- What Is Linux?

Linux is an open-source operating system. Just like you install Windows to run a regular PC,

a server needs an operating system suited to servers, and Linux is one of them.

## \- Installing VMware

A single computer can't run two operating systems at once. So we use a virtual machine to run

Linux virtually on our computer. For that, we'll use an application called VMware.

See the link below.

[yeolceo.tistory.com/31](https://yeolceo.tistory.com/31)

## \- Downloading CentOS 7

To run Linux in a virtual machine, you need an ISO file that contains the operating system.

We're going to use CentOS 7.

[mirror.kakao.com/centos/7.8.2003/isos/x86\_64/](http://mirror.kakao.com/centos/7.8.2003/isos/x86_64/)

Follow the URL above and download the ISO file labeled DVD, shown below. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_1.webp)

The download takes a while. Feel free to read an episode of a webcomic in the meantime, haha.  

## \- Installing CentOS 7

Now that both VMware and the ISO file are ready, let's use them

to run CentOS 7.

First, click File > New.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_2.webp)

When the screen below appears, select the ISO file you downloaded. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_21.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_22.webp)

This is where you set the name. You might create other virtual machines later,

so pick a name you'll recognize. Naming it after its purpose works well. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_3.webp)

This step sets how much disk space the virtual machine is allowed to use.  

If you're tight on space, 20GB is fine. If you have room, go with around 50GB.

The option below decides whether the disk is stored as a single file or split into multiple files.

A single 50GB file gives you a slight performance boost.

But it can be inconvenient when you need to copy data around, so I chose multiple files.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_4.webp)

Click the Customize Hardware button marked in yellow below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_5.webp)

This is where you decide how much performance to give the virtual machine. 

It comes out of your own computer's resources, so only be generous if you have plenty to spare.

This is my work computer, so I kept it modest... Below is the memory setting.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_6.webp)

This is the number of CPU cores. It affects performance, but one core is fine if it's just for development.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_7.webp)

This is the network setting. Bridged mode connects the VM to the network through your host OS. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_8.webp)

That's all the settings done. Now just keep going.

You'll get a screen like the one below. 

Not much left now! Choose your language.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_9.webp)

You'll see a screen like this. 

Follow along below and go through the parts you need.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_10.webp)

This is the keyboard layout. Click Keyboard and add English. 

That's because we'll be typing in both English and Korean.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_11.webp)

Back on this screen, choose the installation destination.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_12.webp)

This is the device we're installing to. Here we configure the partitioning.

Select the disk with 40GiB of free space, choose to configure partitioning yourself, then click Done.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_13.webp)

Set up the partitions as shown below. Give /boot and swap just the basic amount,

and '/' gets everything else, so dump all the remaining space into the slash.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_14.webp)

When you're done, select Network on the screen below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_15.webp)

Clicking it shows the screen below. It'll be turned off at first. Configure it to match your computer.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_16.webp)

Click Begin Installation and it starts.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_17.webp)

If it's just for your own development use, setting the root password is enough. 

root is the account with full privileges, 

and a user is an account with limited privileges.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_18.webp)

Create the account right away. I strongly recommend writing the password down somewhere.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_19.webp)

Nice work. Now wait for the installation to finish, and you'll see a screen like the one below. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_20.webp)
