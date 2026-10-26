---
title: "Uncaught SyntaxError: Unexpected token '<'"
labels: ["TS","JS","react","Uncaught"]
published: false
date: 2020-12-23T10:18:32+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 63
tistoryUrl: "https://yeolceo.tistory.com/63"
tistoryCategory: "TS, JS/react"
tistoryTags: ["Uncaught"]
tistoryPostedAt: "2020-12-23 10:18:32"
language: ko
bloggerPostId: "3775347678913541048"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/63/img.webp)

이 미친 에러를 알게 되었습니다. 저는 react에서 이문제가 일어났습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/63/img_1.webp)

코드 2에서 위와 같은 에러가 떴고 찾아본 결과 코드 1이 있으면 해결이 됩니다.

```html
</head>
    <title>React App</title>
    <base href="/" />                               -코드 1  - 해결용 코드 
    <script src="free.player.1.8.4.js"></script>    -코드 2  - 문제의 스크립트
  </head>

  <body>
    <noscript>You need to enable JavaScript to run this app.</noscript>
    <div id="root"></div>
  </body>
```

**\- 알아본 결과**

<base href="URL" /> 

base 요소는 페이지 내의 모든 상대 url의 기준을 잡아주는 요소입니다. 

제 경우에는 url을 변경하면 다른 페이지를 실행하는 기능이 있었는데 그중 한 페이지만 이런 문제가 나왔습니다. 

내부 코드를 전부 지워도 같은 결과가 나오더군요. 다른 react 파일은 이런 경우가 없었습니다.

즉 특수한 경우에 일어나고 모든 url이 아닌 미정의 url 에서 base url 이문제가 되는 경우가 생깁니다.
