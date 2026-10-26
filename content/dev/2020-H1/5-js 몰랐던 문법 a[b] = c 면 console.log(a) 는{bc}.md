---
title: "js 몰랐던 문법 a[b] = \"c\" 면 console.log(a) 는{b:\"c\"}"
labels: ["TS","JS","react","ES6"]
published: true
date: 2020-05-21T16:42:07+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 5
tistoryUrl: "https://yeolceo.tistory.com/5"
tistoryCategory: "TS, JS/react"
tistoryTags: ["JS","ES6","js","es6"]
tistoryPostedAt: "2020-05-21 16:42:07"
language: ko
bloggerPostId: "5837244889589580121"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/5/img.webp)

#### **\-에러이미지**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/5/img_1.webp)

jsx 문법인 거 같은데 이런 식으로 표현하는걸 처음 봐서 글로 기록한다.

변수를 파싱한 다른 변수에 배열 값으로 넣고 문자열을 넣으면 json형태로 출력한다. nextState 그대로 setState도 가능하다. 

이런 식으로 json형태로 쉽게 만들고 사용하는 경우가 꽤 보입니다.  

```html
let userName="test";
let nextState={}
nextState[userName] = "value";
console.log(nextState);

//결과값 {test: 'value'}
```
