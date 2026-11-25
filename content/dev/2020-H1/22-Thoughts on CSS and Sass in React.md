---
title: "Thoughts on CSS and Sass in React"
labels: ["TS","JS","react","Archive"]
published: true
date: 2020-06-11T16:48:43+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 22
tistoryUrl: "https://yeolceo.tistory.com/22"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react"]
tistoryPostedAt: "2020-06-11 16:48:43"
language: en
bloggerPostId: "1080635768732894250"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/22/img.webp)

Below is a rundown of some new things I learned about CSS.

I kept the page short, so just read it as "oh, so that exists."

```html
$red: #fa5252;
$orange:#fd7e14;
$yellow:#fcc419;
$green:#40c057;
$violet:#7950f2;

@mixin square($size){
    $calculated:32px * $size;
    width:$calculated;
    height:$calculated;
}

.SassComponent{
  display:flex;
  .box {
    background:red;
    cursor:pointer;
    transition: all 0.3s ease-in;
    &.red{
        background: $red;
        @include square(1);
    }
    &.orange{
        background: $orange;
        @include square(2);
    }
    &.yellow{
        background: $yellow;
        @include square(3);
    }
    &.green{
        background: $green;
        @include square(4);
    }
    &:hover{
        background: $violet;
    }
  }
}
```

That's how it's used. It has curly braces and semicolons, so this is SCSS.

You turn the parts of your CSS you need into variables. You can also split it into files and pull them in with `@import`.

include-media makes responsive CSS easy to write,

and open-color lets you add colors conveniently.

If you save a file as `.module.css`, CSS Modules kick in. With modules, in `className`

you `import style` and, if the CSS has a class called `testCss`, reference it as `style.testCss`.

The referenced name gets a unique value. Since it's set in `className`, that element gets the CSS you referenced.

**Last up is a library called styled-components.**

```html
import React from 'react';
import styled , {css} from 'styled-components';

const Box = styled.div`
	background:${props => props.colorr || 'blue'};
	padding: 1rem;
	display:flex;
	`;

const App =()=>{

  return (
    <div>

 				<Box colorr="green">

				</Box>
		</div>
  );
}
export default App;
```

In React, I've pulled most of my UI from Material or antd. That'll probably continue,

but this style of CSS felt genuinely useful and practical.

Notice the prop I'm receiving is `colorr`, with an extra "r." I liked that you can set up

your own element names and props instead of variable names the library declares.

I think it'd also work well with media queries when building responsive sites.

I hope you learned something new.
