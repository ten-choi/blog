---
title: "Linux File Transfer Made Easy with WinSCP"
labels: ["ETC","ETCLanguage","Linux","win","Archive"]
published: true
date: 2021-01-13T18:02:56+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 76
tistoryUrl: "https://yeolceo.tistory.com/76"
tistoryCategory: "ETC/ETCLanguage"
tistoryTags: ["리눅스","리눅스","리눅스","win","리눅스"]
tistoryPostedAt: "2021-01-13 18:02:56"
language: en
bloggerPostId: "1434143741498156615"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img.webp)

#### **\- WinSCP** 

An **open-source** program for Windows that supports **SFTP** and **FTP**.

It helps you send files from your local computer to a remote server, or receive files from it.

(SFTP = SSH File Transfer Protocol)

(FTP = File Transfer Protocol)

#### **\- Download**

First, google it — search for **WinSCP**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_1.webp)

This is the official **WinSCP** site. Click the marked area to start the download.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_2.webp)

If a download prompt appears, click Continue, and once it's done, click it to **run** it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_3.webp)

When the installer appears, just go through it as is.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_4.webp)

Unless you have a specific reason not to, I recommend the **full upgrade**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_5.webp)

When the installation is **complete** as shown below, click **Finish**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_6.webp)

That's it for installation. Launch it from the **icon**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_7.webp)

#### **\- How to Use It**

When you launch it from the **icon**, the **login window** below appears.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_8.webp)

**1.**  Set the file protocol to **SFTP**. **SFTP** is the **SSH** File Transfer Protocol. **SSH** is essentially a secure replacement for **Telnet**, a network connection protocol.

**2.** Enter the IP of the Linux machine you want to transfer files to in **Host name (H)**, and the port the Linux machine has open for remote access in **Port number (R)**. If you're not sure, for testing you can turn off that Linux server's **firewall** and practice.

3\. For **User name (U)**, use the **root** account, and for **Password (P)**, enter that account's password.

Once everything is entered correctly, click the **Login button**.

If you **get the password wrong**, you'll see this message. Enter the correct password.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_9.webp)

### **And Just Like That**

The program is up and running. Try moving some files and you'll see it's a really **useful free open-source program**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_10.webp)

That's how to transfer files easily with **WinSCP**.

I hope it went smoothly. Happy coding!
