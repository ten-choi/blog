---
title: "react 에서 css 및 Sass에 관한 고찰"
labels: ["TS","JS","react"]
published: true
date: 2020-06-11T16:48:43+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 22
tistoryUrl: "https://yeolceo.tistory.com/22"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react"]
tistoryPostedAt: "2020-06-11 16:48:43"
language: ko
bloggerPostId: "1080635768732894250"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/22/img.webp)

이 밑으로 css에 관한 새로운 지식에 관한 나열입니다. 

이런 것도 있구나 하고 봐주시게끔 간결한 페이지로 만들었습니다.

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

 이런 식으로 사용합니다. 중괄호랑 세미콜론이 있으니 scss입니다.

css의 필요한 부분을 변수화 해서 사용합니다.  @import를 이용해서 파일 분할을 하고 사용할 수도 있습니다.

include media를 사용해서 반응형 css를 짜기 용이하고 

open color를 사용해서 색도 편하게 추가할 수 있습니다. 

. module.css로 저장하면 css module이 적용되는데 모듈화 해서 사용하면 className에 

호출할 때 import style , css에서 testCss라는 css 객체일 때  style.testCss로 호출하면 됩니다.

호출된 변수는 고윳값을 가지고 있습니다. classname에 기입했기 때문에 그 엘리먼트는 호출한 css값을 갖습니다.

**마지막으로 styld-components라는 라이브러리입니다.** 

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

 react 하면서 ui를 대부분 material 나 antd에서 가져왔습니다.  앞으로도 그런 부분은 있지만

이런 식의 css 스타일링은 유용하면서도 쓸만하다는 느낌이 들었습니다.

props로 받아주는 부분을 보면 colorr이라고  r을 하나 더 붙였습니다. 라이브러리에서 선언되어있는

변수명이 아닌 제가 직접 만든 엘리먼트명이나 props를 설정해서 사용할 수 있다는 점이

꽤 괜찮았네요.  media를 이용하면서 반응형 웹을 만들 때도 같이 사용하면 좋겠다는 생각이 들었습니다.

새로운 지식이 되었길 바랍니다.
