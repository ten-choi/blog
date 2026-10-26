---
title: "React의 Redux 데이터 구조 이해하기 1"
labels: ["TS","JS","react","Redux"]
published: true
date: 2020-06-17T10:30:58+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 27
tistoryUrl: "https://yeolceo.tistory.com/27"
tistoryCategory: "TS, JS/react"
tistoryTags: ["Redux","react","redux","react"]
tistoryPostedAt: "2020-06-17 10:30:58"
language: ko
bloggerPostId: "8247502940592062471"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/27/img_3.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/27/img_4.webp)

**이번 프로젝트는 리액트에서 주로 사용되는 데이터 구조인 리덕스에 대해서 알아보려 합니다.**

**이해하기 쉬운 카운터를 이용해서 설명할 예정입니다. 제가 느낄 때 기본 패턴보다 Ducks 패턴이 더 편리하여**

**Ducks패턴을 사용하였습니다.** 

**\*Ducks 패턴이란 리듀서 함수, 액션 타입 변수, 액션 생성 함수를 하나의 파일에 작성하는 방식입니다.**

 **(이번 프로젝트에서는 모듈이라는 폴더를 생성합니다.**

               **counter 컴포넌트가 있다면** **위의 3가지를 하나의 파일에 몰빵 합니다. )**

* * *

## \# 데이터 구조 및 흐름

 기초적인 구조를 먼저 설명하고 넘어가겠습니다. 자세한 부분은 진행하면서 풀어가겠습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/27/img.webp)

컴포넌트 : 모든 웹에 보이는 뷰를 담당합니다. 보이기만 하는 껍데기입니다. 

컨테이너 : 컴포넌트에서 보이는 기능들을 여기서 처리합니다. 컴포넌트에 +1이라는 버튼이 있다면

               +1을 어떻게 처리할지 컨테이너에서 정하는 역할을 합니다.

모듈 : 컨테이너에서 정해준 역할을 실행하여 데이터를 변경합니다.

![출처 -> https://blog-kr.zoyi.co/channel-ios-redux/](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/27/img_1.webp)

데이터의 흐름입니다. 이해하시는 과정에서 다시금 보게 될 것입니다.

전체적인 흐름: 컴포넌트(View)의 버튼(어떤 기능)을 클릭합니다. 그러면 컴포넌트의 데이터를 관리하는 용도의

컨테이너에서 클릭된 기능을 dispatch (action)합니다. 클릭된 기능은 액션 타입으로 구분해줍니다. 액션이 실행됐다면

그에 맞는 타입의 리듀서가(모듈) 클릭된 기능을 이행합니다. 이행한 값은 스토어에 저장됩니다. 스토어에 새로운 값이

저장되면 View를 리 렌더링 해줍니다.  

※ 위의 설명을 어느 정도 이해한 다음 프로젝트를 이행하시길 부탁드립니다.

## \# 프로젝트 만들기

  create-react-app를 통해 기본 앱을 만듭니다.

  해당 프로젝트의 명은 redux-tutorial로 생성해주세요. 

  npm install create react-app redux-tutorial 

  생성한 프로젝트에서 redux를 사용해주기 위해 라이브러리를 추가해줍니다. 

   npm install redux react-redux --save       \* --save는 package.json파일에 본인이 설치한 라이브러리를 명시하는 기능입니다.

  기본 설치된 App.js 에서 불필요한 부분을 제거하면 이런 형태가 됩니다.

```html
import React from 'react';

const App =()=> {
  return (
    <div className="App">

    </div>
  );
}

export default App;
```

## \# 사용할 컴포넌트 준비하기

#### \- 카운터 컴포넌트

  먼저 src경로에 components 폴더를 생성합니다. components 폴더는 모든 UI 부분을 담당할 것입니다. 

  components 폴더에 카운터 컴포넌트를 만들어줍니다. 

```html
import React from 'react';

const Counter =({number, onIncrease, onDecrease})=> {
  return (
    <div>
        <h1>{number}</h1>
        <button onClick={onIncrease}>+1</button>
        <button onClick={onDecrease}>-1</button>
    </div>
  );
}

export default Counter;
```

```html
import React from 'react';
import Counter from './components/Counter'

const App =()=> {
  return (
    <div className="App">
        <Counter number={0}/>
    </div>
  );
}

export default App;
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/27/img_2.webp)

보시는 부분과 같이 잘 나오셨다면 성공입니다.

counter 컴포넌트는 인자를 받는데 그중에 일단

number값만 넘겨준 것뿐입니다. 

## \# 카운터 모듈

경로입니다. './modules/counter'  모듈에 counter 파일을 생성합니다. 사전에 말씀드렸던 

**리듀서 함수, 액션 타입 변수(이해하기 쉽게 변수라 말했지만 const로 선언합시다), 액션 생성 함수**를

여기에 몰빵 합니다. 

```html
//액션 타입 변수

const INCREASE = 'counter/INCREASE';  //액션을 하기위한 타입을 설정합니다.
const DECREASE = 'counter/DECREASE';   

//액션 생성 함수

export const increase =()=>({type:INCREASE });  //타입을 설정했으니 export로 내보내줍니다.
export const decrease =()=>({type:DECREASE });  //디스패치 해줄때 이걸 사용하는겁니다.
                                               //그래야 밑에 리듀서보면 case에서 씁니다.
const initialState={    //영어그대로 초기화를 해주는 부분입니다.
  number:0
}

//리듀서 함수 

function counter(state = initialState , action){

  switch (action.type) {  //타입에 맞는 행동을 진행합니다. 데이터를 변경합니다.
    case INCREASE:
    return{
          number:state.number+1
    };
    case DECREASE:
    return{
          number:state.number-1
    };
    default:
      return state;
  }
}
export default counter;
```

모듈에서 만약 counter 이외에 여러 개의 컴포넌트를 다루게 된다면 모듈을 하나로 합 체! 하는 것이 가능합니다.

combineReducer는 리듀서 합체한다는 소리입니다. 그리고 counter만 불러줬습니다. 

test 1이라는 임의에 컴포넌트를 더해준다면 이런 형식이 될 것입니다. 저희는 counter만 쓰기 때문에 test 1 들을

지워줍시다.

```html
import {combineReducers} from 'redux';
import counter from  './counter';
import test1 from  './test1';

const rootReducer= combineReducers({
  counter , test1
});

export default rootReducer;
```

## \# 스토어

src 경로에 있는 index.js 파일을 확인합시다.

밑에 주석 처리한 2개의 부분만 추가해주었고 나머지는 기본 상태입니다. 바로 추가해줍시다.

```html
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import * as serviceWorker from './serviceWorker';

import {createStore } from 'redux';   //여기가 스토어입니다. 흐름도 이미지 참고해주세요
import rootReducer from './modules'    //여기서 리듀서 불러쥼 index로 선언했으니 /index생략가능

const store = createStore(rootReducer);
ReactDOM.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
  document.getElementById('root')
);

// If you want your app to work offline and load faster, you can change
// unregister() to register() below. Note this comes with some pitfalls.
// Learn more about service workers: https://bit.ly/CRA-PWA
serviceWorker.unregister();
```

흐름도를 지속적으로 확인해주세요. 데이터 구조(data Layer)에 대해 알고 사용하는 것이 중요합니다.

createStore는 말 그대로 스토어 생성입니다. 저장하는 곳을 만들어줍니다.

그리고 store를 선언해줄 때 리듀서를 인자로 넣어줍니다. initialState를 초기값으로 받아줍니다.

그리고 redux의 Provider를 불러와줍니다. 말 그대로 제공자, 공급자의 의미인데 

스토어가 초기화되거나 새로운 값이 들어올 때마다 리 렌더링 해주는 컴포넌트입니다.

이 컴포넌트를 사용하려면 store를 props로 전달해주어야 합니다.

redux관련 에러가 뜨시는 분들은 잠깐 멈추시고 npm install redux react-redux --save를 실행해주시기 바랍니다.

리덕스를 사용하기 위한 라이브러리입니다.

```html
import React from 'react';
import ReactDOM from 'react-dom';
import './index.css';
import App from './App';
import * as serviceWorker from './serviceWorker';

import {createStore } from 'redux';
import rootReducer from './modules'
import {Provider} from 'react-redux'

const store = createStore(rootReducer);
ReactDOM.render(
  <Provider store={store} >
    <App />
  </Provider>
    ,
  document.getElementById('root')
);

serviceWorker.unregister();
```

벌써 스토어의 초기 설정까지 완료했습니다.  축하드립니다. 

[http://www.yeolceo.com/28](http://www.yeolceo.com/28)

글을 보고 잘 따라와 주시고 계셨다면 **다음 페이지로** 넘어가 주세요.
