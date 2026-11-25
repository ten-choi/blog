---
title: "[ IntelliJ ] Fixing Garbled Korean Characters"
labels: ["IDE","Editor","Intellij","Archive"]
published: true
date: 2024-03-18T10:08:53+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 213
tistoryUrl: "https://yeolceo.tistory.com/213"
tistoryCategory: "IDE, Editor/Intellij"
tistoryTags: ["IntelliJ","KR"]
tistoryPostedAt: "2024-03-18 10:08:53"
language: en
bloggerPostId: "8595644152951090768"
---
I'm keeping a copy here in case the original gets deleted or changed. This is copied from the post at the link below.  
If this causes any problem, I'll delete the post or change its contents.  
[https://www.lesstif.com/java/intellij-file-console-encoding-121012310.html](https://www.lesstif.com/java/intellij-file-console-encoding-121012310.html)

# Fixing Garbled Korean Characters in IntelliJ (File and Console Encoding Settings)

If Korean text shows up garbled when you start a WAS or run an app in IntelliJ, it's usually because the encoding is misconfigured.

In most cases you'll be using UTF-8, so just set the encoding correctly as follows.

## File/Console Encoding Settings

1. Go to **Settings** → **Editor** → **File Encodings**.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/213/img.webp)

**2\.** Set the **Global** and **Project** encoding (1), and also set the encoding for **properties** files (2).

If the Korean text in your properties files is escaped like the line below, enabling "Transparent native-to-ascii conversion" will convert it automatically for display.

```clean
## \uC804\uC5ED
```

Plain text

Copy

CODE

## VM Option Settings

1. Select **Help** → "**Edit Custom VM options**".

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/213/img_1.webp)

2\. Add the file and console encoding options to the VM options.

```ini
-Dfile.encoding=UTF-8
-Dconsole.encoding=UTF-8
```

Plain text

Copy

CODE

3\. Once you're done, select **File** → "**Invalidate Caches**".

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/213/img_2.webp)

4. Select **"Invalidate and Restart"** to clear the caches and restart IntelliJ.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/213/img_3.webp)
