---
title: "Super Simple! Install Python and Run It in Atom"
labels: ["Python","atom","Archive"]
published: true
date: 2020-10-21T17:18:46+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 55
tistoryUrl: "https://yeolceo.tistory.com/55"
tistoryCategory: "Python"
tistoryTags: ["python","atom","atom","python"]
tistoryPostedAt: "2020-10-21 17:18:46"
language: en
bloggerPostId: "1172676210967289036"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img.webp)

We'll download Python, then download Atom and run our code there. If you'd rather use VS Code, skip the Atom part.

## **\-Downloading Python**

First, search for Python and click the **Downloads** link on the official site.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_1.webp)

You'll see a screen like the one below. Pick the Windows version.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_2.webp)

Usually you'd use the latest version for learning and the stable version for real development.   
But here we need **3.8** to work with Atom.   
When I tried 3.9, it wasn't compatible with Atom's **script package**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_3.webp)

Scroll down and install the one highlighted in blue: Download -> Windows x86-64 executable installer

Once the file is downloaded, run it as administrator. 

First checkbox: install Python for all users on Windows.

Second checkbox: add Python to the PATH environment variable.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_4.webp)

The screenshot says 3.9 because I tried it with 3.9... Please use 3.8!

That said, if you install the wrong one by mistake, I've added a fix at the very bottom. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_5.webp)

Once the install is done, search for "idle" in Windows and launch Python. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_6.webp)

Let's test Python right away. Just typing 1000 + 1000 gives you the result,

no variables needed.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_7.webp)

## **\-Downloading Atom**

Now for the main event: installing Atom. We're almost there. 

[atom.io/](https://atom.io/)

The download button can be hard to spot. It's that red one over there... 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_8.webp)

Launch Atom and open Settings with the shortcut \[Ctrl\] + \[ , \].  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_9.webp)

This is an autocomplete package that gives you hints while coding in Python. It's a must-have, so grab it: autocomplete-python 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_10.webp)

If the one above is a must-have, the one below is required: without it, nothing runs. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_11.webp)

The package downloaded above adds script-running support to Atom. These are the Windows ones.

Below are the shortcuts from that package's docs. Ctrl + Shift + B just worked for me, though.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_12.webp)

Almost done. Create a new page with New File. 

Then write some simple code like this: print('print your code');

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_13.webp)

Press Ctrl + S and a dialog asks where to save it. In my case, I made a folder

called test on the desktop and saved it there. Make sure you use the .py extension.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_14.webp)

Now for Ctrl + Shift + B. 

Run your Python code with Shift + Ctrl + B. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_15.webp)

If, like me, you unfortunately went with 3.9, you'll see the warning below. Just click the URL in it.

Python was not found but can be installed from the Microsoft Store: [https://go.microsoft.com/fwlink?linkID=2082640](https://go.microsoft.com/fwlink?linkID=2082640)

Bottom line:

3.9 runs fine on Windows, but it doesn't seem to be compatible with Atom's script package yet.

If you happened to download 3.9, use the URL above to get 3.8 instead.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_16.webp)

Did everything run for you?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/55/img_17.webp)

That's how to run Python in Atom. Happy coding!
