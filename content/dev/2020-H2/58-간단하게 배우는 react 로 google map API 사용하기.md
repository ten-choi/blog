---
title: "간단하게 배우는 react 로 google map API 사용하기"
labels: ["TS","JS","react"]
published: true
date: 2020-11-12T18:49:59+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 58
tistoryUrl: "https://yeolceo.tistory.com/58"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react","react"]
tistoryPostedAt: "2020-11-12 18:49:59"
language: ko
bloggerPostId: "2702960808769021019"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/58/img_10.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/58/img_11.webp)

간단하게 배우는 리액트로 구글 맵 api 사용하기

3개월 평가판 입니다.  적당히 쓰고 해지 하시는걸 추천드립니다.

[cloud.google.com/maps-platform](https://cloud.google.com/maps-platform)

google 로그인을 하셨다면 위의 url로 들어가서 시작하기를 눌러주세요.  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/58/img.webp)

시작하기 누르면 아래화면 바로나옴

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/58/img_1.webp)

저만 그런지 모르겠는데 계속 눌러도 잘안넘어가더라고요 ;; 구글인뎅;

잘 누르다보면 요런 화면이 나옴니다 체크 2개는 필수고 아래거는 선택입니다.

그리고 보이는 빨간 체크 부분 눌러서 진행해주세요

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/58/img_2.webp)

동의하고 또 새로고침하면 요런화면나옴

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/58/img_3.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/58/img_4.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/58/img_5.webp)

완료를 전체적으로 마무리하고 다시 첫화면으로 돌오와서 시작을 눌러주면 됩니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/58/img_6.webp)

이 화면이 나오면 성공ㄷ api 를 눌러줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/58/img_7.webp)

API 및 서비스 눌러줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/58/img_8.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/58/img_9.webp)

자 이제 구글 맵 쓸수있는 api 권한을 얻었습니다. key 값받으려고 여기까지 한겁니다.

자 이제 react를 만들어봅시다. 

react
