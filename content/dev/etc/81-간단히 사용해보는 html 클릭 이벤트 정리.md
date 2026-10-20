---
title: "간단히 사용해보는 html 클릭 이벤트 정리"
labels: ["ETC","Html5","Css3","html"]
published: false
date: 2021-02-02T13:35:55+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 81
tistoryUrl: "https://yeolceo.tistory.com/81"
tistoryCategory: "ETC/Html5, Css3"
tistoryTags: ["html","html5","html5","html5","html5","html5"]
tistoryPostedAt: "2021-02-02 13:35:55"
language: ko
bloggerPostId: "7870004610076838378"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/81/img.webp)

일반적으로 웹을 사용할 때 마우스는 필수적인 요소입니다. html에서는 마우스에 관련된 이벤트를

여러 가지 지원하는데 그 이벤트들을 유용한 것들 위주로 모아놓았습니다.

### \-마우스 클릭 이벤트 모음

**\- onclick**

사용자가 해당 요소를 클릭할 경우 지정된 이벤트가 발생합니다.

```html
<button onclick="function()">Click Here</button>
```

**\-oncontextmenu**

사용자가 해당 요소에서 마우스를 우클릭할 경우 지정된 이벤트가 발생합니다.

```html
<div oncontextmenu="function()" contextmenu="menu">
```

**\-ondblclick**

사용자가 해당 요소를 두 번 연속으로 클릭할 경우 이벤트가 발생합니다.

```html
<div ondblclick="function()">Double Click</div>
```

**\-onmousedown ●**

사용자가 해당 요소 위에서 마우스를 눌렀을 경우 이벤트가 발생합니다.

```html
<div onmousedown="function()">Click Here</div>
```

**\-onmouseup **●****

사용자가 해당 요소 위에서 마우스를 누른 손가락을 떼었을 경우 이벤트가 발생합니다.

```html
<div onmouseup="function()">Click Here</div>
```

**\-onmouseenter ●**

사용자의 마우스 포인터가 해당 요소로 안으로 이동했을 경우 이벤트가 발생합니다.

```html
<img onmouseenter="funcEnter()" src="small.gif" alt="small">
```

**\-onmouseleave **●****

사용자의 마우스 포인터가 해당 요소로 밖으로 이동했을 경우 이벤트가 발생합니다.

```html
<img onmouseleave="funcLeave()" src="Big.gif" alt="Big">
```

**\-onmousemove** 

사용자의 마우스 포인터가 해당 요소 위에서 이동할 때 이벤트가 발생합니다.

```html
<div onmousemove="func()">Move Over Here</div>
```

**\-onmouseover ****●******

사용자의 마우스 포인터가 해당 요소 또는 해당 요소의 하위 요소 중 하나의 안으로 이동될 때 이벤트가 발생합니다.

```html
<img onmouseover="bigImg()" src="big.gif" alt="big">
```

**\-onmouseout ●**

사용자의 마우스 포인터가 해당 요소 또는 해당 요소의 하위 요소 중 하나의 밖으로 이동될 때 이벤트가 발생합니다.

```html
<img onmouseout="smallImg()" src="small.gif" alt="small">
```

이상 간단하게 정리한 마우스 클릭관련 이벤트였습니다. 성실한 코딩 하세요.
