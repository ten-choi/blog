---
title: "이보다 더나은 설명은 없다! React에서 Router 쓰기!"
labels: ["TS","JS","react"]
published: true
date: 2020-06-12T16:14:00+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 23
tistoryUrl: "https://yeolceo.tistory.com/23"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react"]
tistoryPostedAt: "2020-06-12 16:14:00"
language: ko
bloggerPostId: "6909343833694761749"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/23/img.webp)

## **\-React에서 Router란**

**SPA(싱글 페이지 어플리케이션)에서 경로 설정만으로 다른 화면을 보여주는 기술입니다.** 

html 파일로 예를 들어보겠습니다. html에선 보여줄 화면이 3개라면 html 파일 3개가 각각 경로가 되어 

화면에 보여줍니다. 하지만 SPA는 싱글 페이지 이기 때문에 화면이 하나입니다. 그러니까 router 같은

경로 설정을 이용하여 보여주는 화면을 다르게 설정하는것입니다.

\[

router기본 기능 및 qs, params, history 설명입니다. 자주 쓰는 기능을 다뤘습니다.

\]

## **\-React에서 바로 실천해보기**

**npm install create react-app \[원하는 프로젝트 명\]**

****yarn add create react-app \[원하는 프로젝트 명\]****

명령 프롬프트에서 원하는 위치에 해당 명령을 실행해줍니다.

cra \[****create react-app****\]를 통해 프로젝트 설치가 완료되었다면

라우터 기능을 사용하기 위한 패키지 모듈을 install 해줍시다 ->  **npm installl react-router-dom**

**그리고 npm start로 실행해줍니다!!**

실행이 완료되셨다면 아래와 같은 목록이 생길텐데요.

index를 실행해줍니다. 처음엔 **<React.StrictMode>**라고 써있는 컴포넌트가 App을 감싸고있을것입니다.

이 컴포넌트는 잠제적인 문제를 알려주기위한 리액트 자체적인 기능이므로 삭제하셔도 괜찮습니다.

과감히 삭제합니다. 그리고 아래와같이 **<BrowserRouter>** 를 입력해줍니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/23/img_1.webp)

```html
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import * as serviceWorker from './serviceWorker';

import {BrowserRouter}  from 'react-router-dom';      //요거

ReactDOM.render(
<BrowserRouter>  <App />
</BrowserRouter>
 ,
  document.getElementById('root')
);
```

위와같이 감싸준 이유는 App 컴포넌트 이후로 사용하는 곳에는 router기능을 사용하겠다는 의미입니다.

App.js 에서 본인이 원하는 컴포넌트 아무거나 2개 만드시면 됩니다. 저는 간단하게 AppA와 AppB를 만들었습니다.

아래와 같이 route를 해주려면 다른 js파일이 있어야 하기 때문에 만들어주는 것입니다. 

보여주는 것을 달리하기 위해서입니다. 

아래와 같이 코드를 작성해주세요. 

```html
import React from 'react';
import {Route , Link} from 'react-router-dom';
import AppA from './AppA';
import AppB from './AppB';

const App =()=>{

  return (
    <div>
		<ul>
			<li>
				<Link to="/">아니</Link>
			</li>
			<li>
				<Link to="/AppB">안녕</Link>
			</li>
		</ul>

			<Route path="/" component={AppA} exact={true} />
			<Route path="/AppB" component={AppB} />
		</div>
  );
}
export default App;
```

install 했던 react-router-dom 을 통해 Link와 Route 기능을 불러옵니다.

경로와 컴포넌트를 기입하면 경로가 맞을 때 그 컴포넌트를 호출합니다.

exact는 정확하게 맞을 때만 구분하겠냐는 질문입니다. true로 설정했습니다.

3000 포트로 실행하시면 주소창에 경로 설정 변경만으로 컴포넌트를 다르게 띄우는 것이 보일 겁니다.

하지만 직접 주소창을 변경하는 게 불편하기 때문에 router에는 Link기능이 있습니다. 

위에 코드를 따라가시면 링크는 경로를 변경해주는 기능이란 것을 알 수 있습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/23/img_2.webp)

App A 와 App B 는 App 컴포넌트와 같은 디렉토리에 만들어주세요. 

![캡쳐1](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/23/img_3.webp)

이렇게 나오시면 성공입니다. 하단부의 문자열은 제가 표시용으로 적었습니다.

<Route path={\['/AbbA', '/AbbB'\]} component={AppB} /> 이 코드를 사용하면 2가지 경로로 하나의 컴포넌트를

불러줍니다. 저는 쓸 일이 단 한 번도 없었습니다.

**자 이제 파라미터 값을 사용해봅시다. 주소창의 경로를 값으로서 활용하는 방법입니다.**

```html
import React from 'react';
import {Route , Link} from 'react-router-dom';
import AppA from './AppA';
import AppB from './AppB';
import Profile from  './Profile';

const App =()=>{

  return (
    <div>
					<ul>
					<li>
						<Link to="/AppA">A </Link>
					</li>
					<li>
						<Link to="/AppB">B </Link>
					</li>
						<li>
							<Link to="/profile/itzy">있지 </Link>
						</li>
						<li>
						<Link to="/profile/me">나</Link>
						</li>
					</ul>

				<Route path="/AppA" component={AppA} exact={true} />
				<Route path={['/BBB', '/AppB']} component={AppB} />
				<Route path="/profile/:username" component={Profile} />

		</div>
  );
}
export default App;
```

여기서 집중하 실부분은 Profile 이란  밑에 있는 코드가 들어간 js파일이 생성된 것과 3번째 라우터입니다.

:username라고 적었다는 것은 profile/어쩌고   의 경로를 가지고 있다면 

해당 경로로 이동하는 동시에 어쩌고를 파라미터 값으로 넘겨주는 것을 의미합니다. 하단의 match를 보시면 됩니다.

```html
import React from 'react'

const data={
  itzy:{
    name:'류진',
    description:'미녀'
  },
  me:{
    name:'yeol',
    description:'coding slave'
  }
};

const Profile =({match}) =>{

  const {username} = match.params;
  const profile = data[username];
  if(!profile){
    return <div>존재하지않는 사용자입니다.</div>
  }

    return(
          <div>
            <h3>
              이름 {username} description ({profile.description})
            </h3>
          </div>
    )
}

export default Profile;
```

match라는 객체는 라우트 컴포넌트를 사용할 때 params 값을 참조합니다. 제가 만든 객체 아니고 match   
라는 객체가 내부에 선언되어있습니다.

코드를 실행해보시면서 이해해보시는 걸 추천합니다. 간단한 예제일수록 실행해보는 것이 중요합니다.

**자 이제 쿼리 스트링을 사용해봅시다. 주소창의 경로를 값으로서 활용하는 두 번째 방법입니다.**

**이것까지만 해도 주소창 이용하는 기초는 끝난다고 봅니다.**

아주 쉽게 하나만 남겨놨습니다. AppA 만들어놨던 거 쓸 겁니다.

```html
import React from 'react';
import {Route , Link} from 'react-router-dom';
import AppA from './AppA';
import AppB from './AppB';
import Profile from  './Profile';

const App =()=>{

  return (
    <div>
					<ul>
						<li>
						<Link to="/AppA?itzy=류진">나</Link>
						</li>
					</ul>

				<Route path="/AppA" component={AppA}  />

		</div>
  );
}
export default App;
```

 웹을 해보셨던 분이라면 쉽게 이해하실 겁니다.? 다음에 변수와 값을 설정해서 넘겨주는 방식입니다.

```html
import React from 'react';
import qs from 'qs'

const AppA =({location})=>{

  const query = qs.parse(location.search,{
    ignoreQueryPrefix:true   //물음표 표시 생략위한 설정
  });
  const showQs =query.itzy;
  return (
    <div>
        <h1>Itzy
        {showQs }은 미녀입니다. </h1>
    </div>
  );
}
export default AppA;
```

 qa를 npm에서 인스톨합니다. match와 마찬가지로 location은 qs를 가져오기 위한 객체입니다. 

qs.parse를 쓴 이유는 파싱 안 해주면 location.search를 받아와도 값이 변질됩니다. 

[https://www.npmjs.com/package/qs](https://www.npmjs.com/package/qs) 자세히 보려면 qs npm 참조하세요!

값을 잘 넘겨받는다면 qs까지 완료가 됐습니다.

**마지막으로 history 하나만 보고 마치겠습니다. 쓸만한 기능이라 남깁니다.**

<Route path="/history" component={History}  /> 이 코드 하나를 기존 App에 추가합시다.

그리고 js파일 하나를 생성합니다.

```html
import React , {Component} from 'react'

export default class History extends Component{

    handleGoBack=()=>{
      this.props.history.goBack();
    }
    handleGoHome=()=>{
      this.props.history.push('/');
    }

      componentDidMount(){
          this.unBlock = this.props.history.block('짜잔');
      }

      componentWillUnmount(){
        if(this.unblock){
          this.unblock();
        }
      }

    render(){
      return(
        <div>
            <button onClick={this.handleGoBack}>뒤로</button>
            <button onClick={this.handleGoHome}>홈으로</button>
        </div>
      )
    }
}
```

뒤로 가기가 존재합니다. 사실 꽤 중요한 기능입니다. html은 페이지를 변경하지만 spa는 구조가 다르기 때문에

경로가 변경되었을 뿐 html처럼 페이지가 변경된 것이 아니기 때문에 존재함에 감사하며 써야 합니다.

최대한 간결하게 코드 블록을 만들었기 때문에 이해를 위한 설명보단

이해를 위한 노력이 덜 들게 하는 코드이길 바랍니다.
