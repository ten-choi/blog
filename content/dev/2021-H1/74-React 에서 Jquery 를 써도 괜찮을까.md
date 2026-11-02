---
title: "React 에서 Jquery 를 써도 괜찮을까?"
labels: ["react","npm"]
published: true
date: 2021-01-10T12:15:16+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 74
tistoryUrl: "https://yeolceo.tistory.com/74"
tistoryCategory: ""
tistoryTags: ["react","react","npm","react"]
tistoryPostedAt: "2021-01-10 12:15:16"
language: ko
bloggerPostId: "7808598192268833316"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/74/img-png.webp)

**Jsp**와 **Jquery**를 사용해본 사람이 React로 넘어오면 저처럼 습관적으로 쓸지도 모릅니다.

#### **발단**

**React**를 사용하다 마우스 이벤트를 사용해야 할 타이밍이 왔습니다. 

**mouseup** 기능이었는데 예전에 **Jquery**에서 사용한 기억이 문득 났습니다.

**React**에서 **Jquery**사용방법을 찾아 **mousedown과** **mouseup을** **React**에 적용하였습니다.

이후 **React**에서 **dom**을 직접 수정하는 것을 별로 좋아하지 않는다는 글을 보게 되었습니다.

(Jquery는 React를 거치지 않고 document를 직접 수정합니다)

문서를 찾아 돌아다니다 보니 **Vanilla Js**와 **Jquery**를 비교하며 성능을 논하는 글도 보였고요.

**Jquery**를 개발하신 개발자분도 트위터에서 **Jquery**가 **Js를** 대체할 수는 없다고 말했습니다. 

#### **결론**

**React에서는** ****Jquery를**** 쓰지 않는 것이 바람직합니다. 결국 찾다 보니 **html**에서 **mouseup을** 기능적으로 지원하는 글도 발견하게 됐습니다.  **w3schools** 공식 홈페이지에서 **onmouseup Event**라는 기능이 있습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/74/img_1-png.webp)

그럼 **React**에도 있을 것 같아서 검색 패턴을 동일하게 한 후 **React**를 붙여서 검색했습니다.

공식문서에 설명이 다 있더라고요. 뭐든 설명서대로 해야 합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/74/img_2.webp)

설명서에 있는 대로 사용합시다. 기괴한 변신로봇을 만들지 맙시다..... 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/74/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/74/img_1.webp)
