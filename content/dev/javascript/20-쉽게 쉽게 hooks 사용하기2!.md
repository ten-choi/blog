---
title: "쉽게 쉽게 hooks 사용하기2!"
labels: ["TS","JS","react"]
published: false
date: 2020-06-11T12:39:27+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 20
tistoryUrl: "https://yeolceo.tistory.com/20"
tistoryCategory: "TS, JS/react"
tistoryTags: ["React","react","react","react"]
tistoryPostedAt: "2020-06-11 12:39:27"
language: ko
bloggerPostId: "4113427759734154764"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/20/img.webp)

hooks를 쉽게 사용해봅시다. 일단 실행부터 해보고 구조를 뜯어보는 방식이 이해하기 쉽다고 생각합니다.

이전에 했던 reducer의 복습을 한번 할 겁니다.

**useReducer 기출 변형**

```html
import React, {useReducer }from 'react';

function reducer(state, action){

  console.log(`action의 name   ->${action.name}`);
  console.log(`action의 value  ->${action.value}`);
    return{
      ...state,
      [action.name]:action.value
    };
}
const App =()=>{

  const [state, dispatch]= useReducer(reducer, {user:'' , nickname:''});
  const {user , nickname} = state;

  const onChange =e=>{
    console.log(e.target);
    dispatch(e.target);
  }
  return (
    <div>
        <input name="user" value={user} onChange={onChange} /> <br />
        <input name="nickname" value={nickname} onChange={onChange} /> <br />
          <b>이름:</b>{user}<br />
          <b>닉네임:</b>{nickname}
    </div>
  );
}

export default App;
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/20/img_1.webp)

이전의 useReducer와 dispatch방식은 그대롭니다.  일단 onChange를 집중해봅시다.

e.target으로 값을 가져옵니다. 그러면 콘솔에 보이시는 것처럼 <input 구문이 통째로 출력됩니다. 

input 자체를 파라미터로 dispatch 해주는 것입니다. 그러면 이게 어떻게 되느냐

input에서 보이는 건 name과 value입니다. action의 type자리에 name과 value를 넣어줬다고 생각하면 됩니다.

그리고 switch 할 때처럼 return을 해줍니다.... state는 초깃값의 불변성을 위해 미리 선해줍니다. 그 후 

action name과  action value를 하게 된다면 이전 시간에 설명드렸던 reducer의 동작 방식과 똑같이 동작합니다.

어차피 switch case는 return을 하기 위한 타입 설정입니다.

결론적으론 input의 name을 초기 변수와 이름을 같게 하였고 값은 대입해주면 됩니다. 

```html
switch(action.type){
    	case 'INCREASE':
        return{ value: state.value +1 };
```

실행을 해보시면서 console과 대조해가면 훨씬 간편하게 이해할 수 있습니다.

**useMemo란 본인이 생각한 값이 변경되었을 때만 리 렌더링 하는 hook입니다.**

```html
import React, {useState , useMemo }from 'react';

const getAverage = numbers =>{
		console.log('평균값 계산 함수 실행중');
		if(numbers.length ===0)return 0;
		const sum = numbers.reduce((a,b)=>a+b);
		return sum/numbers.length;
}

const App =()=>{

	const [list, setList] =useState([]);
	const [number, setNumber]= useState('');

	const onChange =e=>{
		setNumber(e.target.value);  };
	const onInsert=e=>{
		const nextList = list.concat(parseInt(number));
		setList(nextList);
		setNumber('');
	}
	const avg = useMemo(()=>getAverage(list),[list]); //주목하실부분

  return (
    <div>
			<input value = {number} onChange = {onChange} />
			<button onClick={onInsert}>등록</button>
				<ul>
					{list.map((value, index)=>(
						<li key={index}>{value}</li>
					))}
				</ul>
				<div>
					평균값 : {avg}
				</div>
		</div>
  );
}
export default App;
```

 useMemo라인을 지우셔도 무방합니다. console이 어떻게 출력되는지 확인해주세요.

개념은 간단합니다. list라는 배열 하나를 만들어서 input 이끝나고 list배열에 인자로서 추가할 때 list에 값이 변경되니까

그때 출력 값 avg를 변경해주겠다는 의미입니다. 

위쪽에 map.reduce 는 첫 번째 인자는 0에서 시작하고 두 번째 인자는 list의 값으로 시작합니다.

reduce의미 그대로 줄인다는 뜻은 코드의 양을 줄이겠다는 의미로 a+b 는 a를 누적 값으로 놓고 b는 list의 값을 넣어 list의 모든 값을

더할 때까지 더해주겠다는 의미입니다.

코드를 console.log('debug 1') console.log('debug 2') 이런 식으로 분류하여 구조를 이해하시는 것도 하나의 방법입니다.

**마지막으로 useRef입니다. 클래스형 컴포넌트의 ref와 동일한 기능입니다.**

```html
useRef

    	const element = useRef(null);
		element.current.focus();
		ref={element}
```

사용법이 너무너무 쉬워서 아주 간단하게 표시했습니다. 

위의 코드에서 useRef를 import 해줍니다. 그리고 input 내부에 ref를 설정합니다.  ref 내부에는 코드 블록과 같이

본인이 useRef를 설정해준 변수를 기입해주시면 됩니다. 

등록이 진행되는 insert코드의 최하단에 기입합니다. 등록이 끝나는 동시에 element.current.focus();를실행하고

해당 엘리먼트인 input에 커서가 띄워지는 것을 볼 수 있습니다. 

제기준에서 쓸만한 hooks들을 나열해봤습니다. 도움이 되었길 바랍니다.
