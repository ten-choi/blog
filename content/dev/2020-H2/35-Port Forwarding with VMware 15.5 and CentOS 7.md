---
title: "Port Forwarding with VMware 15.5 and CentOS 7"
labels: ["OS","Linux","vmware","vmware15.5","centos7","Archive"]
published: true
date: 2020-07-17T18:06:18+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 35
tistoryUrl: "https://yeolceo.tistory.com/35"
tistoryCategory: "OS/Linux"
tistoryTags: ["vmware","vmware15.5","centos7"]
tistoryPostedAt: "2020-07-17 18:06:18"
language: en
bloggerPostId: "1771074455575628408"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_10.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_11.webp)

## \- What Is Port Forwarding?

Port forwarding, or port mapping, is an application of network address translation that redirects a communication request from one combination of IP address and port number to another while the packets traverse a network gateway, such as a router or firewall.

\- Wikipedia

## \- Port Forwarding with VMware 15.5 and CentOS 7

To actually see that the port is connected, we'll run a Node.js server on CentOS.

(This post is about port forwarding, but the verification step assumes some basic knowledge of npm and Node.js.)

On VMware's start screen, if you've installed CentOS, click it in the list and open its settings.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img.webp)

Set it to VMnet8 under Custom. (We're going with NAT.)

Once the basic setup is done, we need to set up port forwarding. However,

VMware Workstation 15.5

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_1.webp)

doesn't have the Edit toolbar shown in the screenshot.

There are two ways around this.

Options

1.  Download VMware 15.5 Pro first and set this file aside. -> Remove the VMware DLL, go back to the regular version, and use the folder you set aside.

2.  I've uploaded a Google Drive link. (It's my first time sharing one, so I don't know about download limits and such.) Just download the regular version and use this.

**[drive.google.com/file/d/1ai69cSLs3rPq8W79zP-xoC6BcAi6gbrR/view?usp=sharing](https://drive.google.com/file/d/1ai69cSLs3rPq8W79zP-xoC6BcAi6gbrR/view?usp=sharing)**

That's what you need to do port forwarding in VMware 15.5.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_2.webp)

After installing, you'll get files like the ones above. Run the one highlighted in yellow.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_3.webp)

If the subnet IP and mask aren't set, you can use the same values as mine. Just make sure they don't overlap with any other IPs.

Once you see the screen above, click NAT Settings...

Some of the default settings will already be filled in.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_4.webp)

But since this is your first time, you won't have the part highlighted in yellow.

Click the Add button.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_5.webp)

1: the port the host PC will listen on. The type right below it means it's received as a TCP port.

2: enter the IP of your CentOS 7 VM in VMware. If it's not a static IP, note that it'll change when you restart.

3: enter the port on the CentOS 7 VM you want to connect to.

4: write a description or the reason for this port forwarding rule.

I used the screenshots below as reference. In the CentOS 7 terminal, type ip addr to see the IP.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_12.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_13.webp)

In other words, with this setup, whatever runs on port 5000 in CentOS 7 can be reached on port 10000 on the host.

Now click OK on all the settings.

That's it for port forwarding. Congrats!

* * *

Now let's check that it's connected properly.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_6.webp)

On CentOS, we'll run it like this. I made up the path myself, and the index file is a Node.js file

I created. I'll assume you can install Node.js and npm on your own.

Use mkdir to create whatever path you like.

Then use npm init to set up the project's package.json. It's fine to just run npm init and hit Enter through everything.

When that's done, create index.js with the vi editor.

If the file doesn't exist, it gets created; if it does, you edit it.

(It's easier to do all of this after getting root with su -.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_7.webp)

I created the file below. For Express, I installed it with npm install express --save

before using it. (If typing doesn't work, press i to enter insert mode.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_8.webp)

When you're done, press Esc and type :wq in that order. That saves the file and exits.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_9.webp)

Now run node index.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_14.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/35/img_15.webp)

As described above, port forwarding is complete: port 5000 is now reachable on port 10000.

(If you already know port forwarding well, Bridged mode just works like this.)

If you really want to use Bridged, just set the network type to Bridged from the start.

Since the router assigns a new IP, it works just like port forwarding on a regular PC to show a website on your smartphone:

allow the port number on CentOS 7 and enter the IP as-is.

For example, something like 192.168.22.1:5000.

That's port forwarding with VMware 15.5 and CentOS 7. Thanks for reading!
