---
title: "react Context API 이해하기"
labels: ["TS","JS","react","context"]
published: false
date: 2020-06-15T15:12:26+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 26
tistoryUrl: "https://yeolceo.tistory.com/26"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","context","react"]
tistoryPostedAt: "2020-06-15 15:12:26"
language: ko
bloggerPostId: "1013753328096067605"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/26/img.webp)

**이번에 설명해볼 내용은 Context API에 관해서입니다.**

redux와 같은 상태 관리를 위한 라이브러리입니다. react의 내장 라이브러리로서 사용 가능합니다.

create-react-app으로 리액트 프로젝트를 하나 생성해줍시다. 후에

```html
import React, {createContext, useState} from 'react';

const ColorContext = createContext({color:'pink'});

export default ColorContext;
```

위와 같은 js 파일을 하나 생성합니다.

createContext는 초기값 설정이라고 보시면 됩니다. json 타입으로 color를 pink로 초기화해주었습니다.

```html
import React from 'react';
import ColorContext from './Color';

const App=()=>{

        return(
        	<div>
              <ColorContext.Consumer>
              { value=>(<div style={{width:'60px' ,height:'50px' , background: value.color }}/>)}
              </ColorContext.Consumer>
            </div>
        )
}
export default App;
```

간단하게 App에다 바로 넣어주었습니다. createContext의 Consumer를 사용하면

children처럼 컴포넌트 내부에서 value값을 가져올 수 있습니다. 하지만

중괄호 하나를 더생성하고 컴포넌트를 불러주어 그 안에 value.color값을 넣어주었습니다.

이런 패턴을 Render Props라고 합니다.

쉽게 생각하면 전역 변수를 가져와서 사용한 것입니다.

여기서 초기값을 변경하는 법이 있습니다.

```html
import React from 'react';
import ColorContext from './Color';

const App=()=>{

        return(
        	<div>
            <ColorContext.Provider value={{color:'green' }}>
              <ColorContext.Consumer>
              { value=>(<div style={{width:'60px' ,height:'50px' , background: value.color }}/>)}
              </ColorContext.Consumer>
            </ColorContext.Provider>
          </div>
        )
}
export default App;
```

Provider를 이용하는 것입니다. 전부 createContext를 기준으로 한 컴포넌트로 사용되는 것을 볼 수 있습니다.

Provider를 사용하면 Context에 초기값이 있다면 대신하고 없으면 채워주는 컴포넌트입니다.

벌써 사용법과 변경법을 끝냈습니다. 아주 간단하고 이해하기 쉽게 적었기 때문에 쓸모없어 보이고

감이 오지 않을 수 있습니다.

그런 분들을 위해 밑의 3가지 파일을 준비했습니다.

**첫 번째 컴포넌트입니다.**

```html
import React from 'react'
import {ColorConsumer} from './Color'

const ColorBox =()=>{

  return (
        <ColorConsumer>
              { ({state}) =>(
                <>
                <div  style={{ width:'64px' , height:'64px', background: state.color}} />
                <div  style={{ width:'32px' , height:'32px', background: state.subcolor}} />
                </>
            )}
        </ColorConsumer>
  );
}
export default ColorBox;
```

 ColorBox라는 보여주기 전용 컴포넌트를 작성합니다.

ColorConsumer는 아래와 같은 코드 중 하나를 선언을 했기 때문에 사용 가능합니다.

const ColorConsumer = ColorContext.Consumer;   //아래의 코드와 같음

const {Consumer: ColorConsumer} = ColorContext; //위의 코드와 같음

즉 ColorContext.Consumer 컴포넌트에서 value가 아닌 state 기준으로 보여줍니다.

**2번째 컴포넌트입니다.**

```html
import React, {createContext, useState} from 'react';

const ColorContext = createContext({

    state:{color: 'black' , subcolor: 'red'},
    action: {
        setColor: ()=>{},
        setSubcolor:()=>{}
    }
  });

const ColorProvider = ({children})=>{
      const [color , setColor] = useState('black');
      const [subcolor , setSubcolor] = useState('red');

      const value = {
        state:{color, subcolor},
        action: {setColor , setSubcolor}
      };

    return(
      <ColorContext.Provider value={value} >{children}</ColorContext.Provider>
    );
};

const {Consumer: ColorConsumer} = ColorContext;
export {ColorProvider, ColorConsumer};
export default ColorContext;
```

useState를 사용해줍니다. 초기값을 createContext로 설정해준 다음 

하단부에 Provider를 바로 만들어줍니다.  value를 그냥 써도 되지만 redux처럼 구분 지어줘서 사용하기 위해

value내에 state와 action을 나눠줬습니다.

```html
import React, {useState} from 'react'
import ColorBox from './ColorBox';
import {ColorProvider , ColorConsumer} from './Color'

const App =()=>{

  return (
        <div>
          <ColorProvider>
          <div>
              <ColorBox />
          </div>

            <ColorConsumer>
              { ({action})=>(<button onClick={()=>{action.setColor('blue') }}>asdf</button>)}
            </ColorConsumer>
          </ColorProvider>
        </div>
      );
}
export default App;
```

**마지막으로 출력하는 부분입니다.** App 컴포넌트에 종합하는 부분입니다.  단,

action을 이용하여 useState를 사용해주기 때문에 값을 변경 가능합니다.  이로서 redux와 비슷한 기능을

간단하게 사용할 수 있는 것입니다. 간편한 기능일 경우 redux와 성능 편차가 크지 않습니다.

hooks처럼 context도 발전 가능성이 높으니 짚고 넘어가면 좋다고 생각합니다.
