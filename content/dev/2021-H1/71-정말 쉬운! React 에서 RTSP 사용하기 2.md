---
title: "정말 쉬운! React 에서 RTSP 사용하기 2"
labels: ["TS","JS","react","rtsp"]
published: true
date: 2021-01-04T15:15:10+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 71
tistoryUrl: "https://yeolceo.tistory.com/71"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react","react","rtsp"]
tistoryPostedAt: "2021-01-04 15:15:10"
language: ko
bloggerPostId: "2734495861273184845"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img.webp)

\-해당 글은 streamedian 사이트의 rtsp 기술을 참조합니다. 윈도에서 개발하시는 분들이 RTSP 하시기에 적합하며

실무라면 라이선스 구매나 리눅스 환경에서 실행을 위한 공부가 필요할 수 있습니다.

#### **\-필요 프로젝트 준비**

**React**의 프로젝트 내에서 **Rtsp**를 실행할 수 있게끔 해야겠죠?  

**\[정말 쉬운! React에서 RTSP 사용하기 1 -YEOL\]에서** 사용했던 **Streamedian 프로젝트**를 준비합니다.

그다음 **npm crate react-app \[프로젝트명\]을** 통해 새 프로젝트를 만들어줍니다.

**Streamedian** 프로젝트를 살펴봅시다!

이 프로젝트에서 **Rtsp**실행에 관계된 파일들을 **React** 프로젝트에 옮겨주어야 합니다. free.player.1.8.4.js 는 소켓 통신으로 **Rtsp**를 가능하게 해 주는 기능이 들어있는 코드입니다.

따라서 **[free.player.1.8.4.js을](http://free.player.1.8.4.js)** **Rtsp****프로젝트**로부터 **React 프로젝트**의 **public** 경로에 복사 후 붙여 넣기 해줍시다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_1.webp)

**[free.player.1.8.4.js](http://free.player.1.8.4.js)** 파일을 옮겼다면 사용해야겠죠? **index.html** 파일에서는 해당 자바스크립트를 

사용한다는 코드를 넣어줍니다.  ->  **index.html을** 클릭해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_2.webp)

아래의 코드를 참고하셔서 **<head>** 태그 사이에 저런 형태로 끼워 넣어 주시면 됩니다.

```html
<head>

    <script src="free.player.1.8.4.js"></script> // 요거만 넣어주세요

  </head>
```

**Rtsp** 기능을 하는 코드를 옮겨주었다면 그다음에는 기능을 실행하는 부분을 옮겨줘야겠지요?

**React 프로젝트**의 src 경로에 **Streamedian이라는** 폴더 하나를 생성합니다.

아래의 파일들은 실행을 위한 부분의 컴포넌트입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_3.webp)

**Rtsp** 프로젝트에서 아래 빨간 줄이 있는 부분입니다.  (css는 수정해보고 싶으시다면 옮기셔도 좋습니다)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_4.webp)

파일을 옮기는 부분은 끝났습니다!!!  벌써 반 왔습니다 힘내세요!

#### **\-React 프로젝트 수정**

**React 프로젝트**의 **Streamedian** 폴더를 살펴봐주세요. **[StreamedianPlayer.jsx](http://StreamedianPlayer.jsx)** 파일은 video 재생을 위한 부분과 아닌 부분이 섞여있는 컴포넌트입니다.

사용하지 않는 부분을 과감히 제거해줍니다. 아래처럼 **video** 만남 겨주시면 됩니다.

```html
render() {
    return (
      <div>
        <video id={this.props.id} controls autoPlay>
          {this.props.children}
        </video>
      </div>
    );
  }
```

그리고 사용하지 않는다면 **import** 해주는 부분도 없애주어야겠지요? **import**는 **React** 만 남겨줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_5.webp)

**Rtsp의** 기능인 **[free.player.1.8.4.js](http://free.player.1.8.4.js)** 가 있고 영상을 실행하는 **player** 부분인 **Streamedian** 폴더가 존재합니다.

그러면 **App.js** 컴포넌트에서 호출할 일만 남았겠네요..? 그럼 **Streamedian에서** 호출할 부분인 **index**를 살펴봅시다.

저처럼 **index** 파일을 수정해주세요. 필요한 부분만 남겨준 형태입니다.

```html
import React from 'react';
import StreamedianPlayer from './StreamedianPlayer';
// import './index.css';

const App = ({url, id}) => (
	<div>
		<StreamedianPlayer id={id} >
			{ <source  src={url} type="application/x-rtsp" /> }
		</StreamedianPlayer>
	</div>
);

export default App;
```

**id와** **rtsp** **url** 이 영상 실행을 위한 핵심 요소이기 때문에 꼭 사용해야 합니다.

매 컴포넌트에서 쉽게 사용하기 위해 props로 값을 전달한 것이고요. 그래야 호출할 땐 <Streamedian id={} url={} /> 방식으로 쉽게 호출할 테니까요. 

**자 이제 모든 준비가 끝났습니다**. **React**의 **App.js** 파일을 정리해줍니다.

```html
import './App.css';

const App=()=>{
  return (
    <div className="App" >

    </div>
  );
}

export default App;
```

그리고 저희가 만든 폴더의 경로 (폴더를 경로로 지정하면 해당 폴더의 index.js를 호출합니다)를 사용하여 **Streamedian를** 호출합니다. 그와 동시에 당연히 **id와** **url** 도 넘겨주세요!

```html
import './App.css';
import Streamedian from './Streamedian';

const App=()=>{
  return (
    <div className="App" >

      <Streamedian id="test" url="rtsp://여러분들의 rtsp url" />
    </div>
  );
}

export default App;

(이때 제가 사용했던 rtsp는 제 소유가 아니어서 공개할 수 없는 점 양해 부탁드립니다.)
```

**Rtsp**가 잘 실행되셨나요?  

![가린거는 좀 다보여주기 그래서요....](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_6.webp)

더욱 정확한 정보를 원하신다면 **공식 사이트**를 찾아주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/71/img_7.webp)

쉽고 간편하게 이해하셨길 바랍니다. 성실한 코딩 하세요.
