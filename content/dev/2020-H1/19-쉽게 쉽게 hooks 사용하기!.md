---
title: "쉽게 쉽게 hooks 사용하기!"
labels: ["TS","JS","react"]
published: false
date: 2020-06-11T09:43:07+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 19
tistoryUrl: "https://yeolceo.tistory.com/19"
tistoryCategory: "TS, JS/react"
tistoryTags: ["React","react","react","react"]
tistoryPostedAt: "2020-06-11 09:43:07"
language: ko
bloggerPostId: "2594606696538078140"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/19/img.webp)

hooks 란 react 16.8 버전부터 도입된 기능으로 함수형 컴포넌트에서 할 수 없었던

상태 관리를 가능하게 해주는 내장 라이브러리입니다.

**useState useEffect** **useReducer 설명합니다.** 

create react app을 이용하여 새로운 프로젝트를 만들어 줍시다!

**먼저 useState를 설명드리겠습니다 딱 한 페이지 분량으로 설명합니다.**

클래스형 컴포넌트의 setState와 동일하게 값이 변경되면 리 렌더링을 해줍니다. 

하지만 useState는 사용할 때 요렇게 사용한다. 간단하게 짜 봤는데 설명드리자면

```html
import React , {useState} from 'react';

const App =()=>{

const [data , setData] = useState(0);

		return(
        	<div>
            	데이터값:{data}
            	<button onClick={()=>{setData(data+1); }} >증가</button>
            </div>
        )
}

export default App;
```

 useState의 파라미터는 문자열이든 숫자든 관계없이 배열의 첫 번째 인자를(현재는 data) 초기화해주는

값으로 사용됩니다. 그리고 두 번째 인자는 (현재 setData) 저 값을 밑의 onClick처럼 사용해주면 됩니다. 

setData에 파라미터를 대입한 후 실행하면 data에 그 값을 대입하고 해당 함수형 컴포넌트를 리 렌더링 해줍니다.

사용해보면 setState보다 간편하다고 느껴집니다. 저는 그랬습니다. 

**다음 useEffect입니다 기능이 2가지라 2페이지 분량입니다.** 

useEffect는 컴포넌트가 렌더링 될 때마다 특정 작업을 수행하도록 하는 hook입니다. 

클래스형 컴포넌트에선 componentDidMount, componentDidUpdate를 hooks에서는 useEffect

사용한다고 생각하시면 됩니다. 코드 보면서 설명해드리겠습니다. 

```html
import React , {useState , useEffect } from 'react';

const App =()=>{

const [data , setData] = useState(0);

useEffect(()=>{          //여기가 useEffect 사용하는부분
	console.log('렌더링 확인하는거 보이십니까?');
});

		return(
        	<div>
            	데이터값:{data}
            	<button onClick={()=>{setData(data+1); }} >증가</button>
            </div>
        )
}

export default App;
```

react를 실행해서 3000 포트로 보고 계시다면 개발자 도구

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/19/img_1.webp)

F12 키를 눌러서 콘솔 창을 확인해줍시다.

밑의 화면과 같은 콘솔창을 띄우시면 됩니다. 

처음 렌더링과 onClick로 인한 리 렌더링이 될 때마다 

console.log의 문자열이 출력될 것입니다.

didmount와 didupdate를 동시에 수행합니다. 

단 mount 시에만 사용하고 싶은데 didupdate까지 원하시지 않는다면 코드 블록의 useEffect 부분에서

```html
import React , {useState , useEffect } from 'react';

const App =()=>{

const [data , setData] = useState(0);

useEffect(()=>{        
	console.log('렌더링 확인하는거 보이십니까?');
}, [] );  // 요기로 확인하세요~!

		return(
        	<div>
            	데이터값:{data}
            	<button onClick={()=>{setData(data+1); }} >증가</button>
            </div>
        )
}

export default App;
```

빈 배열 하나를 useEffect의 두 번째 파라미터에 추가하시면 됩니다. 그럼 didmount 만 사용할 수 있습니다. 

아니면 **didupdate를 실행하는데** 특정값이 업데이트될 때만 실행하고 싶다면   

```html
import React , {useState , useEffect } from 'react';

const App =()=>{

const [data , setData] = useState(0);

useEffect(()=>{        
	console.log('렌더링 확인하는거 보이십니까?');
}, [data] );  // 요기로 확인하세요~!

		return(
        	<div>
            	데이터값:{data}
            	<button onClick={()=>{setData(data+1); }} >증가</button>
            </div>
        )
}

export default App;
```

 예를 들어 useState의 첫 번째 인자인 useEffect의 2번째 파라미터의 배열 인자로 넣어주게 된다면

인자 값이 변할 때마다 console.log 가 출력되는 걸 확인하실수 있습니다. 매우 간단합니다. 

마지막 정리로 useEffect를 사용하여 DidMount 나 DidUpdate가 기능하기 직전에 특정 작업을 수행하고 싶다면

```html
useEffect(()=>{        
	console.log('렌더링 확인하는거 보이십니까?');

    return ()=>{    // 이렇게 사용합니다. 
    	console.log('cleanup = 뒷정리나 청소 라는 의미인데 업데이트 하기전 뒷마무리 정도로..생각 '); 
    }
}, [] );
```

요렇게 리턴해주시면 됩니다. 어떤 책에서는 뒷정리 함수라고 칭했습니다.  

**축하드립니다. 벌써 주요한 hooks 기능 2가지를 마스터하셨습니다.** 

**다음은 useReducer입니다. redux를 알고 오셨다면 이해가 용이합니다. 난이도가 소폭 올라갑니다.** 

useReducer는 useState보다 더 다양하게 컴포넌트의 상황에 따라 값을 업데이트해줘야 할 때 사용하는 hook입니다. 

리듀서는 현재 상태, 업데이트를 위해 필요한 정보를 담은 액션 값을 전달받아 새로운 값을 반환하는 함수입니다. 

```html
import React , { useReducer} from 'react';

function reducer(state, action){
	switch(action.type){
    	case 'INCREASE':
        return{ value: state.value +1 };
        case 'DECREASE':
        return{ value: state.value -1 };
        default :
        return state;
    }
}

const App =()=>{

  const [state, dispatch]= useReducer(reducer, {value :0 } ) ;
		return(
        	<div>
  	         데이터값: {state.value}
            	<button onClick={()=>{ dispatch({type:'INCREASE'} ) }} >증가</button>
                <button onClick={()=>{ dispatch({type:'DECREASE'} ) }} >감소</button>
                {console.log(useReducer())}
                {console.log(dispatch)}
          </div>
        );
}

export default App;
```

reducer 용 함수를 2개의 파라미터를 가 진상태로 만들어줍니다. 

첫 번째 파라미터는 사용할 변수이고 두 번째 파라미터는 타입입니다. 위의 function reducer의 switch에서 보시면

타입에 따라서 실행할 케이스를 구분해줍니다.

그러면 본격적으로 사용해봅시다.   일단 useReducer을 선언합시다. 

const { a } = this.state;  이런 문장을 써보셨다면 state내부의 제이슨 타입으로 설정된 a값을 가져오는 구문이란 걸

알 수 있습니다. 아마 위의 배열도 그런 의미로 되어있지 않나 싶습니다.

state, dispatch를 선언해줍니다. state는 값을 나타내고 dispatch는 핸들러입니다.

dispatch에서 타입을 정해주고 실행하면 useReducer를 실행합니다.

value 초기값을 reducer함수에서 타입에 맞게 사용하고 결괏값을 리턴합니다.

console을 찍어보시면 아시겠지만 렌더링을 2번 합니다. 첫 렌더링과 useReducer렌더링

그리고 dispatch를 해주면 렌더링을 다시 2번 해줍니다. 

useEffect와는 조금 다른 느낌으로 사용하시면 될 것 같습니다. 

바로 이해되셨다면 축하드립니다.
