---
title: "Node.js Environment Variables, Simply Explained (and How to Set Them)"
labels: ["TS","JS","nodejs","environment variables","Archive"]
published: true
date: 2020-05-21T10:14:14+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 3
tistoryUrl: "https://yeolceo.tistory.com/3"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["환경변수","node.js","node.js"]
tistoryPostedAt: "2020-05-21 10:14:14"
language: en
bloggerPostId: "8393920036227546440"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/3/img.webp)

Finished installing Node.js? Let's open a cmd window (Command Prompt).

This time we'll check whether it installed correctly and which version of Node.js we downloaded.

#### **\- What Are Environment Variables?**

An environment variable is something you can access from the Command Prompt no matter which directory you're in. For example, without one, a command like the one below only works if you type it inside the folder where Node.js is installed. With the environment variable set, though, the `node -v`  
command (variable) works from any location (path) in the Command Prompt, as shown in the image below.  

(To open the Command Prompt on Windows 10, click the Windows icon in the bottom-left corner of the screen and type cmd.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/3/img_1.webp)

How to run `node -v` without environment variables: copy the path of the directory where you installed Node.js.

In the cmd window (Command Prompt), type  C:\\Users\\name> cd (the path you copied)  and press Enter.

There should be a file called node.exe in that folder.

Then type `node -v` and press Enter. `node` is the command that runs node.exe, and `-v` is an option that prints the Node.js version.

The Command Prompt is described as "the command-line interpreter for OS/2, Windows Embedded Compact, and Windows NT 5.0 and later." If you're curious about the difference between an interpreter and a compiler, a quick Google search will give you plenty of answers.

Setting a path (environment variable) means linking the path ahead of time so you can use the commands in a given folder (e.g. `node -v`) from anywhere.

### **\- How to Set Environment Variables**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/3/img_2.webp)

You can find it through the Control Panel, or just search for "system environment variables" as shown above.

If you're using the Control Panel, go to Control Panel > System > Advanced system settings.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/3/img_3.webp)

You'll see this window. Click Environment Variables.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/3/img_4.webp)

Under System variables, edit the variable named Path.

Click New, paste the path, and confirm. (e.g. C:\\Program Files\\nodejs\\node.exe)

After entering the path, click OK on every window. If typing `node -v` from cmd's default directory prints the version, your environment variable is set.

Nice work! Happy coding.
