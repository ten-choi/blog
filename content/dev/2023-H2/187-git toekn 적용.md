---
title: "git toekn 적용"
labels: []
published: true
date: 2023-08-10T17:44:06+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 187
tistoryUrl: "https://yeolceo.tistory.com/187"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2023-08-10 17:44:06"
language: ko
bloggerPostId: "1106899505775657239"
---
git 오른쪽위에서 셋팅으로 간다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/187/img.webp)

디벨로퍼 셋팅을 본다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/187/img_1.webp)

토큰을 발급한다

사용하고 있는 git source로 간다

```typescript
git remote set-url origin https://${gitUserName}:${token}@{gitUrl}

샘플
git remote set-url origin https://<USERNAME>:<YOUR_TOKEN>@github.com/<USERNAME>/<REPO>.git
```
