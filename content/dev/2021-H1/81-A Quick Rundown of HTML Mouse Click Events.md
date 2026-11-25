---
title: "A Quick Rundown of HTML Mouse Click Events"
labels: ["ETC","Html5","Css3","html","Archive"]
published: true
date: 2021-02-02T13:35:55+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 81
tistoryUrl: "https://yeolceo.tistory.com/81"
tistoryCategory: "ETC/Html5, Css3"
tistoryTags: ["html","html5","html5","html5","html5","html5"]
tistoryPostedAt: "2021-02-02 13:35:55"
language: en
bloggerPostId: "7870004610076838378"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/81/img.webp)

When you use the web, the mouse is pretty much essential. HTML supports a whole range of mouse-related events,

and I've gathered the most useful ones here.

### \-Mouse Click Events

**\- onclick**

Fires the assigned event when the user clicks the element.

```html
<button onclick="function()">Click Here</button>
```

**\-oncontextmenu**

Fires the assigned event when the user right-clicks on the element.

```html
<div oncontextmenu="function()" contextmenu="menu">
```

**\-ondblclick**

Fires when the user clicks the element twice in a row.

```html
<div ondblclick="function()">Double Click</div>
```

**\-onmousedown ●**

Fires when the user presses the mouse button over the element.

```html
<div onmousedown="function()">Click Here</div>
```

**\-onmouseup **●****

Fires when the user releases the mouse button over the element.

```html
<div onmouseup="function()">Click Here</div>
```

**\-onmouseenter ●**

Fires when the user's mouse pointer moves into the element.

```html
<img onmouseenter="funcEnter()" src="small.gif" alt="small">
```

**\-onmouseleave **●****

Fires when the user's mouse pointer moves out of the element.

```html
<img onmouseleave="funcLeave()" src="Big.gif" alt="Big">
```

**\-onmousemove** 

Fires while the user's mouse pointer moves over the element.

```html
<div onmousemove="func()">Move Over Here</div>
```

**\-onmouseover ****●******

Fires when the user's mouse pointer moves into the element or into one of its child elements.

```html
<img onmouseover="bigImg()" src="big.gif" alt="big">
```

**\-onmouseout ●**

Fires when the user's mouse pointer moves out of the element or out of one of its child elements.

```html
<img onmouseout="smallImg()" src="small.gif" alt="small">
```

That's my quick rundown of mouse click events. Happy, diligent coding.
