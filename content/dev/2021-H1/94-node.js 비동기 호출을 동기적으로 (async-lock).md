---
title: "node.js 비동기 호출을 동기적으로 (async-lock)"
labels: ["TS","JS","nodejs","비동기를","restapi","async","async-lock"]
published: true
date: 2021-05-17T09:03:07+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 94
tistoryUrl: "https://yeolceo.tistory.com/94"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["비동기를","restapi","async","async-lock"]
tistoryPostedAt: "2021-05-17 09:03:07"
language: ko
bloggerPostId: "3884363771094736382"
---
장비가 한번에 통신을 여러개 받으면 안되는 기이한 상황이 발생해서 저도 사용해보게됬습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/94/img.webp)

실행을 동기적으로 사용하게해주는 라이브러리입니다. 

예를들어 restApi 를 통해 2가지의 요청을 보낸다면 하나를 마치고 다음 요청을 보내주는 것을 말합니다. 

이걸 쓰면 처리가 하나의 일처리를 순서대로 처리하는 방식입니다.
