---
title: "[ Typescript ] VsCode에서 Typescript Debug 하는법 (How to debug on VsCode When i use Typescript)"
labels: ["TS","JS","typescript","Debug","VSCode"]
published: false
date: 2022-05-11T16:46:23+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 131
tistoryUrl: "https://yeolceo.tistory.com/131"
tistoryCategory: "TS, JS/typescript"
tistoryTags: ["Debug","typescript","VSCode"]
tistoryPostedAt: "2022-05-11 16:46:23"
language: ko
bloggerPostId: "3899491199059336938"
---
#### 환경 

Mac m1, VScode, node 16

#### 개요

typescript를 할 때 debug를 돌리려고 하다 보면 모듈을 못 찾거나 다른 방식으로 하려 하면 손이 좀 갑니다.

## **\- VScode Debug Setting**

괜히 내부에서 돌리지 말고 package.json 에서 돌립시다. 

먼저 server 돌려줄 scripts 하나를 만들어줍시다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/131/img.webp)



아래와 같이 디버그 모드에서 디버그를 내가 설정한 스크립트로 실행합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/131/img_1.webp)

별거 아닌 거에 좀 걸렸네요 후... 성실한 코딩 하세요.
