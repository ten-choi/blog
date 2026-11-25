---
title: "Running Ubuntu Desktop on VMware the Easy Way"
labels: ["OS","Linux","ubuntu","vmware","Archive"]
published: true
date: 2020-07-17T12:00:20+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 34
tistoryUrl: "https://yeolceo.tistory.com/34"
tistoryCategory: "OS/Linux"
tistoryTags: ["ubuntu","vmware","ubuntu"]
tistoryPostedAt: "2020-07-17 12:00:20"
language: en
bloggerPostId: "5795325717038077482"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_8.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_9.webp)

## \- Downloading Ubuntu

Alright, let's go get Ubuntu.

We'll be using version 18.04.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img.webp)

[https://releases.ubuntu.com/18.04/](https://releases.ubuntu.com/18.04/)

Download the [64-bit PC (AMD64) desktop image](https://releases.ubuntu.com/18.04/ubuntu-18.04.4-desktop-amd64.iso).

You can search for it or just follow the link above to get the ISO file.

Once it's downloaded, launch VMware Workstation 15.5 (or whatever version you installed).

## \- Launching VMware

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_1.webp)

Select Player -> File -> New Virtual Machine.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_2.webp)

When you see this screen, select the ISO file you downloaded as the path.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_3.webp)

This is where you set your names and password. **Write them down in a readme.txt file and keep it somewhere safe.**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_4.webp)

I set the disk size to 50 GB. This space comes out of your own computer's storage,

so think it through before entering a number.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_5.webp)

Check that the settings you want are all in place.

In most cases you don't need to customize anything; the defaults are fine. But if your computer is on the low-spec side,

you'll want to choose the memory and CPU cores carefully.

One more thing, though.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_6.webp)

This is the network settings section under Customize. There are three main options.

* * *

\- Bridged

   Lets the VM talk to the outside network through your router. The router assigns IPs to both the host PC and the guest PC.

\- NAT (Network Address Translation)

   The host PC gets an IP, and the VM is assigned one through an internal DHCP. Where Bridged connects through the router,

   NAT connects through the host PC.

\- Host-only

   Only the host PC and the virtual machines can talk to each other. There's no separate IP assignment, so there's no internet either. Unless I

   specifically need it, I've rarely used it.

That's the basic setup done. Click Next through the rest and you'll see a screen like the one below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_7.webp)

Congrats! Once the install finishes, you can log in to the OS with the password you set at the start.
