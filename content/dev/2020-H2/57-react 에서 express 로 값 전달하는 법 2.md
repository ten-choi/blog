---
title: "react 에서 express 로 값 전달하는 법 2"
labels: ["TS","JS","react"]
published: true
date: 2020-11-10T17:47:40+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 57
tistoryUrl: "https://yeolceo.tistory.com/57"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react"]
tistoryPostedAt: "2020-11-10 17:47:40"
language: ko
bloggerPostId: "2921006054799736012"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_12.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_13.webp)

이설명만 하고 바로 리액트 설치하겠습니다!

react에서 express로 값을 넘겨주려면 2가지 라이브러리를 react에 설치해야 합니다.

바로 **axios와 http-proxy-middleware**입니다.

## \-axios

**React**에서 **express**로 get이나 post를 사용하여 값을 넘겨야 하는데 그때 필요한 라이브러리가 **axios**입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img.webp)

## \-http-proxy-middleware 

react에서 express로 restAPI (ex: get이나 post를 사용하여 값 전달하는 기능) 사용하여 값을 넘겨줄 때

node.js 와 react.js는 포트 숫자가 다릅니다. 이경우에  http-proxy-middleware를 사용하여

다른 포트여도 값을 받아줄 수 있게 설치해줍니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_1.webp)

## **\-CRA를 통한 React 파일 생성**

자 이제 설명이 끝났습니다. 이제 리액트를 설치해볼까요?

저는 바탕화면에 client란 폴더를 만들어 그 안에 react 파일을 생성해주겠습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_2.webp)

그다음 명령어를 통해 react-app이라는 명칭의 react 파일을 만들어주었습니다.

npm create react-app react-app 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_3.webp)

자 이제 해당 경로에서 npm start  명령어로 저희가 설치한 react 파일을 실행해줍시다!!!!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_4.webp)

localhost:3000 으로 지정된 react파일이 잘 실행되셨나요?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_5.webp)

첫 원본 코드블럭 입니다.  App.js 컴포넌트이고요.  이 화면을 띄워주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_6.webp)

**이제 내부를 다 지워줍니다.** 

중요하지 않은 항목 부분을 모두 지워주고 아래와 같이 만들어주세요. 클릭을 하면 콘솔이 잘 나오는 지도 확인해주세요!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_7.webp)

너무 손쉽게 완성하셨다고요? 여러분들은 이미 절반은 완성하셨습니다. 

클릭하면 콘솔을 출력하는 아주 간단한 구문입죠!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_8.webp)

나와라 얍! ㅋㅋ;;

react-app을 실행한 명령 프롬프트 화면으로 돌아가서 2가지 라이브러리를 설치해줍시다.

**axios와 http-proxy-middleware    요 두 가지가 포인트입니다!!**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_14.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_15.webp)

****http-proxy-middleware를** 먼저 진행해줍니다.** 

****node.js 포트와 경로를 맞추기 위한 proxy 설정입니다.!****

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_9.webp)

**setupProxy 파일을 만들고 아래와 같이 적어줍시다.**

```html
const { createProxyMiddleware } = require('http-proxy-middleware');  //기능 추가
module.exports = function(app) {

  app.use(createProxyMiddleware( '/api',{   // api가붙어있는 url만 찾을건데
      target: 'http://localhost:5050/',     // 이 경로의 url을 찾을것입니다.
      changeOrigin: true,    
      secure: false                         // 보안은 사용하지않을것입니다.
    })
  );
};
```

**option.changeOrigin**: true/false, Default: false - changes the origin of the host header to the target URL

타깃 url로 헤더를 바꾼단 소리입니다. 저게 쉽게 말하면 저희가 5050 포트를 node.js 에서 사용한다면

3000 포트에서 현재 5050의 기능을 빌려와 사용한다 처럼 이해하시면 좋습니다. 저 상태에서 localhost:3000/api를

하면 값이 나옵니다. node.js 에서 출력되는 값과 같은 값이 나옵니다. (node.js의 /api 경로가 get일 때 테스트 용이함. )

npm을 자세히 보면 여러 가지 설명이 *영어*로 있습니다. 구글 번역기는 최고의 번역기..

axios를 사용한 App component의 최종 형태입니다. 

```html
import logo from './logo.svg';
import './App.css';
import axios from 'axios';   //axios 추가

const App=()=>{

  const send =()=>{
    const client = axios.create();   // axios 기능생성
    const name = '내이름은 코난';   
    client.post('/api' , {name} );   //axios 기능을 통한 post 사용및 name 값 전달.
}

  return (
    <div className="App">
        <button onClick={ ()=>{ send(); }}>보내기 버튼 생성!</button>
    </div>
  );
}

export default App;
```

이전과 별로 달라진 점이 없죠?  버튼을 눌러주면~~~

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_10.webp)

짜잔 이 프롬프트는 현재 node.js의 프롬프트입니다. (react , node.js 둘 다 실행 중이여야 합니다. )

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/57/img_11.webp)

크킄.. 내 이름은 코난 탐저..

여기서 받아준 값이 잘 찍힙니다.~~~~~~~~ 확인이 되셨나요?

최근 일이 마무리되면 3탄으로 이제 express에서 값을 반환하여 다시 react에서 그 값을 사용하는 것으로 마무리하려 합니다.

잘 따라와 주셨다면 고생하셨습니다. 성실한 코딩 하세요.
