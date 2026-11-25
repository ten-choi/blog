---
title: "Setting Up a Git Token"
labels: ["Archive"]
published: true
date: 2023-08-10T17:44:06+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 187
tistoryUrl: "https://yeolceo.tistory.com/187"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2023-08-10 17:44:06"
language: en
bloggerPostId: "1106899505775657239"
---
In GitHub, go to Settings from the top-right corner.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/187/img.webp)

Open Developer settings.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/187/img_1.webp)

Generate a token.

Then go to the git source you're working on and run:

```bash
git remote set-url origin https://${gitUserName}:${token}@${gitUrl}

# Sample
git remote set-url origin https://<USERNAME>:<YOUR_TOKEN>@github.com/<USERNAME>/<REPO>.git
```
