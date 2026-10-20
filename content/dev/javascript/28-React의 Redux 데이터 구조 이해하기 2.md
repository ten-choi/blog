---
title: "React의 Redux 데이터 구조 이해하기 2"
labels: ["TS","JS","react","Redux"]
published: false
date: 2020-06-17T12:18:06+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 28
tistoryUrl: "https://yeolceo.tistory.com/28"
tistoryCategory: "TS, JS/react"
tistoryTags: ["Redux","react","react"]
tistoryPostedAt: "2020-06-17 12:18:06"
language: ko
bloggerPostId: "9035921466615808005"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/28/img_2.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/28/img_3.webp)

지금까지 잘 따라와 주셔서 감사합니다. 이제 카운터의 컨테이너를 만들 것입니다.

그전에 흐름을 한 번 더 살펴봐주세요. 이해가 잘 간다면 다음으로 진행해주세요. 

## #데이터의 흐름

컴포넌트(View)의 버튼(어떤 기능)을 클릭합니다. 그러면 컴포넌트의 데이터를 관리하는 용도의

컨테이너에서 클릭된 기능을 dispatch (action)합니다. 클릭된 기능은 액션 타입으로 구분해줍니다. 액션이 실행됐다면

그에 맞는 타입의 리듀서가(모듈) 클릭된 기능을 이행합니다. 이행한 값은 스토어에 저장됩니다. 스토어에 새로운 값이

저장되면 View를 리 렌더링 해줍니다.  

![출처 -> https://blog-kr.zoyi.co/channel-ios-redux/](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/28/img.webp)

## #카운터 컨테이너

가장 처음 만들 것은 폴더입니다. src경로에 containers 폴더를 만들어줍니다. 

만들었을 때 컴포넌트, 컨테이너, 모듈 폴더가 각각 있으면 잘 따라와 주신 것입니다.

Counter 컴포넌트를 요청해주는 걸 보면 저희는 App컴포넌트에서 Counter컴포넌트를 직접 요청하지 않고

컨테이너를 통해 요청하는 점을 유추할 수 있습니다. 

```html
import React from 'react';

import Counter from '../components/Counter';

const CounterContainer =()=>{  
  return <Counter/>;
};

export default CounterContainer;
```

여기서 redux가 제공하는 connect함수를 사용해야 합니다. 

import {connect} from 'react-redux'; 코드를 선언해줍니다. 밑의 코드를 사용해주기 위한 선언입니다.

```html
export default connect(  mapStateToProps , mapDispatchToProps  )(CounterContainer);
```

### ****connect**** 

       **- mapStateToProps : 리덕스 스토어에 초기화되어있는 데이터(리듀서의 초기값이나 변화된 값이 저장된 곳)를**

                                            ****props를 통해**해당 컴포넌트**(CounterContainer)**로 넘겨주기 위한 함수**

       **- mapDispatchToProps : 액션 생성 함수를 해당 컴포넌트(CounterContainer)의 props로 넘겨주기 위해 함수**

```html
import React from 'react';
import {connect} from 'react-redux';
import Counter from '../components/Counter';
import {increase, decrease } from '../modules/counter';

const CounterContainer =({number, increase , decrease})=>{    //기존 카운터 의 온클릭하면 실행되는거에 컨테이너의 함수를 넣어쥼
  return (<Counter number={number} onIncrease={increase} onDecrease={decrease}/>);
};

const mapStateToProps();    //밑에서 다루기위해
const mapDispatchToProps();  //상세코드를 지웠습니다.

export default connect(mapStateToProps , mapDispatchToProps)(CounterContainer);
```

찬찬히 살표 보겠습니다.

이제 컨테이너에서 컴포넌트를 호출합니다. 즉 컨테이너에 props로 기능을 넘겨주기 때문에

컴포넌트는 껍데기인 것입니다. 그 기능은 저희가 모듈에서 만든 액션 생성 함수를 적용합니다. 

액션생성함수를 모듈에서 호출하고 컨테이너를 통해 컴포넌트에 props로 설정하기에 컴포넌트에서

사용할 수 있는 것입니다.

그렇다면 넘버가 없다고 생각하시는 분들이 있을 수 있습니다.

그래서 connect를 사용하는 것입니다. 저희는 이제 컨테이너를 App에서 호출할 것인데 CounterContainer를

state와 dispatch를 연결해준다음 export 해준다고 코드 마지막에 명시하였습니다. 

그중 state는 리듀서의 state 값이고 저희는 number를 0으로 설정해줬습니다.

위의 코드를 이해하셨다면 아래로 내려갑니다. 

```html
import React from 'react';
import {connect} from 'react-redux';
import Counter from '../components/Counter';
import {increase, decrease } from '../modules/counter';

const CounterContainer =({number, increase , decrease})=>{    //기존 카운터 의 온클릭하면 실행되는거에 컨테이너의 함수를 넣어쥼
  return (<Counter number={number} onIncrease={increase} onDecrease={decrease}/>);
};

const mapStateToProps = state =>({   // 리듀서의 스테이트 값이 store에있고 그걸불러쥼
  number:state.counter.number,
});

const mapDispatchToProps = dispatch =>(
  {
    increase:()=>{dispatch(increase());} ,    //카운터 모듈에서export 한 액션 생성 함수
    decrease:()=>{dispatch(decrease());} ,
});

export default connect(mapStateToProps , mapDispatchToProps)(CounterContainer);
```

여기서에서 조금 디테일한 부분이니까 길게 설명해도 양해 부탁드립니다.

**mapStateToProps :** connect에서 첫 번째 인자 mapStateToProps의 첫번째 파라미터 state에 store의 state값을

대입합니다. store의 state값이란 저희가 카운터 모듈에서 리듀서를 통해 store에 저장된 값을 말합니다.

그래서 state.counter(리듀서 함수명). number 인 것입니다.

**mapDispatchToProps : 1** increase:()=>{ **2**  dispatch( **3**  increase());} 이렇게 끊어서 설명하겠습니다.

1은  <Counter number={number} onIncrease={increase} onDecrease={decrease}/> 이곳에 넣어줄 객체입니다.

위 함수의 number 도 마찬가지고 increase와 decrease도 마찬가지입니다. Counter에 넣어줄 객체를 생성하고 그 안에

데이터를 집어넣는 것입니다. 그런 다음 카운터 컴포넌트에서 increase버튼을 누르면

뒤에 있는 2번 함수를 호출하겠다는 의미입니다. dispatch 또한 리덕스에서 connect의 두 번째 인자 함수의 파라미터에

제공한 객체입니다. dispatch는 호출하면 파라미터(타입이 설정된)를 이용해 리듀서를 실행하겠다는 의미입니다. 

그래서 3 이 액션 생성 함수입니다. dispatch를 실행하면

increase는 export const increase =()=>({type:INCREASE });  이런 식으로 선언해줬었는데 그럼 리듀서에서 

type을 action으로 받아줍니다. 그래서 action.type로 리듀서에서 명시를 하고 디스패치를 하면 액션으로

넘어가는 흐름도 이미지가 있는 것입니다.

**CounterContainer**위의 2가지 기능이 완료된 다음 counterContainer를 실행하는데 이미 앞에서 number, increase, decrease를 만들어주고 리덕스에서 호출한 데이터를 받아줬습니다. 그래서 컴포넌트는 뷰 역할만 할 수 있는 것입니다.

이제 정말 다 왔습니다.

## #마무리 App.js

```html
import React from 'react';
import CounterContainer from './containers/CounterContainer'

const App =()=> {
  return (
    <div className="App">
        <CounterContainer />
    </div>
  );
}

export default App;
```

App컴포넌트에서 카운터 컨테이너를 실행해줍니다. 저는 3100 포트로 설정해줬습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/28/img_1.webp)

여러분도 +1과 -1 이 잘 진행이 되나요? 축하드립니다.

잘 진행이 되길 바라며 redux 이해하기를 이것으로 마치려고 합니다.

추가적인 라이브러리를 사용하거나 구조를 조금 변경할 수 있지만 이해하기 쉬운 부분만 추출하였고

카운터를 예시로 들었습니다.

mvc2던 redux 던 datalayer는 구조만 알면 간단합니다.

리덕스를 처음 배우고 계시다면 제 글이 도움이 되었기를 바랍니다. 지금까지 읽어주셔서 감사합니다.
