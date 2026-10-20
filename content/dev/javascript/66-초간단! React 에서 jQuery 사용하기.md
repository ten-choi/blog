---
title: "초간단! React 에서 jQuery 사용하기"
labels: ["TS","JS","react"]
published: false
date: 2020-12-30T17:34:51+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 66
tistoryUrl: "https://yeolceo.tistory.com/66"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react","react"]
tistoryPostedAt: "2020-12-30 17:34:51"
language: ko
bloggerPostId: "1125016044972694493"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_7.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_8.webp)

**정말 간단하게 배워보는 react에서 jQuery 사용하기입니다.**

### **1\. React Project setting**

 먼저 안 쓰는 react 프로젝트가 있으시면 사용해주시고 없다면 아래의 이미지를 참조하세요.

 create react-app \[파일명\]  명령어를 통해 프로젝트를 생성해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img.webp)

프로젝트 생성을 완료하셨다면

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_1.webp)

npm i jquery --save  명령어를 사용하세요.

해당 프로젝트에 jquery가 인스톨됩니다.  

(구글에서 **npm i jquery를 검색하셔도** 나옵니다 )

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_2.webp)

자 여러분도 프로젝트를 실행하셨나요? 그럼 바로 에디터로 해당 프로젝트를 살펴봅시다.

(다들 vscode 쓰시지만 저는 atom 도 쓰는 편입니다 ㅎㅎ..)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_3.webp)

**2\. react class component에서 사용법**

App.js를 보고 있는 상태가 되셨다면 아래처럼 간단히 정리해줍니다.

```html
import './App.css';
import React from 'react';

class App extends React.Component {
  render(){
    return (
      <div className="App">

      </div>
    );
  }
}

export default App;
```

먼저 class를 통해 보여드리고 function 형태로도 보여드리겠습니다.

npm으로 추가한 jQuery를 사용해주시고 렌더링을 위해 componentDidMount()에 감싸주었습니다.

```html
import './App.css';
import React from 'react';
import $ from "jquery";

class App extends React.Component {

  componentDidMount() {
    $(".target").mousedown(function () {      //마우스 누를떼
      console.log('누름');
    });
    $("button").mouseup(function () {       //마우스 누를뗄떼
     console.log('뗌!');
    });
  }

  render(){
    return (
      <div className="App">
        <button className="target">버튼</button>
      </div>
    );
  }
}

export default App;
```

위와 같은 방법으로 jQuery를 사용해주는 이유는 공식문서에서 설명하고 있습니다.

문서에 따르면 react는 react의 외부 dom에서 일어나는 변화를 인식 못하며 자체적으로 업데이트한다고

명시합니다. 따라서 dom을 다루기 위해 돔을 다루는 생명주기 메서드인 componentDidMount에서

jquey를 적용하고 싶은 요소의 참조를 얻어 사용합니다. 

버튼을 누르고 땔 때 아래와 같이 잘 나오나요?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_4.webp)

**3\. react function component에서 사용법**

이번에는 hooks를 사용하는 버전으로 보여드리겠습니다. 

먼저 함수형의 react component로 정리해줍니다.

```html
import './App.css';

const App=()=>{
  return (
    <div className="App">

    </div>
  );
}

export default App;
```

useEffect와 useState를 활용하여 버튼을 눌렀다 뗄 때 표현되는 text가 변경되도록 코드를 넣었습니다.

```html
import './App.css';
import {useEffect, useState} from 'react';
import $ from "jquery";

const App=()=>{

  const [text, setText] = useState('올해가 끝났습니다.');
  useEffect(()=>{
    $(".target").mousedown(function () {
      setText('나이 한살 추가요')
    });
    $("button").mouseup(function () {
      setText('올해가 끝났습니다.')
    });

    console.log('changed');
  }, []);

  return (
    <div className="App">
      <button className="target">버튼</button>
      <div>{text}</div>
    </div>
  );
}

export default App;
```

버튼을 클릭할 때 아래처럼 이미지가 잘 변경이 되시나요?

![버튼 누른 상태](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_5.webp)

\-버튼 누른 상태

![버튼 눌렀다 뗀 상태](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/66/img_6.webp)

\-버튼 눌렀다 뗀 상태

 간단하게 jquey를 사용하는 법을 알아보았고 사용법 이외에는 react에서도 jquery의 쓰임새와 동일하게

 사용하시면 됩니다.   고생하셨습니다! 성실한 코딩 하세요.
