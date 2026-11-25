---
title: "The Simplest Way to Set Up FTP Downloads on CentOS 7"
labels: ["OS","Linux","ftp","centos","Archive"]
published: true
date: 2020-08-26T11:01:51+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 42
tistoryUrl: "https://yeolceo.tistory.com/42"
tistoryCategory: "OS/Linux"
tistoryTags: ["ftp","리눅스","centos"]
tistoryPostedAt: "2020-08-26 11:01:51"
language: en
bloggerPostId: "6858921466545649054"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img.webp)

 This post covers the GUI version.   
For the CLI version, see here ->  (coming soon, hang tight!)

## \- What Is FTP?

FTP (File Transfer Protocol) is a way to transfer files between a server and a client over TCP/IP.

Think of it as uploading files on the server and downloading them on the client.

## \- What to Do on the Server

Start CentOS 7 in VMware or VirtualBox.

Open a terminal, then run `su -` to switch to root.

We want to set up FTP as simply as possible, but right now the system doesn't have any FTP features.

So install vsftpd with the yum command below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_1.webp)

Once you run it, a new `ftp` folder that wasn't there before shows up under `/var`.

`pub` stands for public, and that's usually where you upload files.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_2.webp)

Now let's create a file for testing. Use the vi text editor to create an `index.js` file.

(Ignore `file1`; that was from my own testing.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_3.webp)

For vi, refer to the image below. Press `i`, type whatever you want, then press Esc to exit insert mode.

`:wq` saves and quits. Enter the command.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_4.webp)

The first command starts the FTP service you installed,

and the second one is `enable`, which makes it start automatically on reboot.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_5.webp)

(I'd already tested this before redoing it for the blog, so the service message doesn't show up on my screen when I run `enable`.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_6.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_7.webp)

We open FTP in the firewall so that clients outside can access the files uploaded to CentOS 7.

And that's already everything on the CentOS 7 side. The server has done its job.

## \- What to Do on the Client

Just download ALDrive.

[https://www.altools.co.kr/](https://www.altools.co.kr/)

We'll use ALDrive to download the files.

You can use your regular Windows machine, or, like me, spin up another Windows VM in VMware.

When you launch ALDrive, you'll see the screen below.

Click My Sites and hit the Add button. I named mine "Server".

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_8.webp)

As shown on the right, it asks for an IP. Enter your CentOS 7 IP.

I used port 21. (You can pick any number as long as it's within the valid port range.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_9.webp)

Unless you set it manually, find your IP with the `ip addr` command.

It's around the second circle in the image below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_10.webp)

Enter the IP you found, then click the Connect button at the bottom right.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_11.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_12.webp)

Now just download the file, and you've completed an FTP download from the CentOS 7 server.

I kept this as simple as I could, so I hope it made sense. Thanks for reading!
