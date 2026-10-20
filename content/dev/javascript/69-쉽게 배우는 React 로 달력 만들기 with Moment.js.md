---
title: "쉽게 배우는 React 로 달력 만들기 with Moment.js"
labels: ["TS","JS","react","react.js"]
published: false
date: 2021-01-02T16:27:39+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 69
tistoryUrl: "https://yeolceo.tistory.com/69"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","react.js","react","react"]
tistoryPostedAt: "2021-01-02 16:27:39"
language: ko
bloggerPostId: "4230238212018405237"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img_5.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img_6.webp)

이번엔 **react**를 사용한 달력 알고리즘을 만드려고 합니다.

완성형이 예쁘다기보단 구조를 보여드리기 위함을 참고해주세요!!

### \-Moment.js 란

**javaScript**에서 날짜 데이터 조작을 하기 쉽게 도와주는 라이브러리입니다. 

(공식 사이트를 참조하시면 학습에 더욱 도움이 됩니다.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img.webp)

### \-React.js 에서 Moment.js 사용 

먼저 다음 명령어 **npm create-react-app \[프로젝트명\]를** 사용하여 react 파일을 생성해줍니다.

(기존 프로젝트가 있다면 쓰셔도 무방합니다.)

**moment.js** 는 저희가 캘린더를 만들기 위한 핵심 라이브러리입니다. 

CMD에서 오른쪽의 명령어를 통해 인스톨해주세요   npm install moment --save

프로젝트를 생성하셨다면 **App.js** 파일을 아래와 같이 정리해줍니다.

**moment.js를** 사용하여 **today.format**으로 현재 연도 및 달을 표시했습니다.

```html
import './App.css';
import {useState} from 'react';
import moment from 'moment';

const App =()=>{

  const [getMoment, setMoment]=useState(moment());     
  const today = getMoment;    // today == moment()   입니다.

  return(
    <div className="App">

        <div className="control">
          <button>이전달</button>
          <span>{today.format('YYYY 년 MM 월')}</span>   //YYYY는 년도 MM 은 달 입니다.
          <button>다음달</button>
        </div>
        <table>
          <tbody>

          </tbody>
        </table>
    </div>
  );
}
export default App;
```

아래처럼 화면이 나오실 겁니다. **moment()는** 선언할 때 현재의 날짜로 초기화되어있습니다.

라이브러리를 어떻게 사용하는지 간단한 방식으로 보여드렸습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img_1.webp)

사이트를 찾아보시면 **moment()**를 사용하는 방법이 나옵니다. 

**subtract는** 빼기 **add**는 더하기입니다. 원하는 날짜 단위를 선택해서 더하고 빼고 합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img_2.webp)

그래서 **useState**를 사용하여 아래처럼 달 단위로 날짜를 변경할 수 있게 설정했습니다.

**clone()** 은 기존의 **moment**가 아닌 새로운 객체를 반환했다는 의미입니다. 

```html
<button onClick={()=>{ setMoment(getMoment.clone().subtract(1, 'month')) }} >이전달</button>
          <span>{today.format('YYYY 년 MM 월')}</span>
          <button onClick={()=>{ setMoment(getMoment.clone().add(1, 'month')) }} >다음달</button>
```

화면을 클릭해보시면 날짜의 변경이 보이실 겁니다.

### \-Calendar 만들기

먼저 첫 주와 마지막 주에 대한 설정을 넣겠습니다. 

firstWeek는   startOf('momth') 그 달의 시작하는 week() 주입니다.

lastWeek는   endOf('momth') 그 달의 끝나는 week() 주입니다.

그 달의 시작주와 끝 주을 알게 되었습니다.  

```html
const App =()=>{

  const [getMoment, setMoment]=useState(moment());

  const today = getMoment;
  const firstWeek = today.clone().startOf('month').week();
  const lastWeek = today.clone().endOf('month').week() === 1 ? 53 : today.clone().endOf('month').week();
```

**lastWeek**에서 쓰인 조건문을 보면 **1**년은 **52**주가 존재하고 며칠이 더 있는데 이 부분을 달력은

53주로써 표현해야 합니다!! 하지만 **moment()는** 내년의 첫 주인 **1**로 표시하기 때문에 

마지막 주가 **1**이라면 **53**으로 표시합니다.

**react**에선 배열을 아래와 같이 표시하면 배열 내의 요소를 전부 하기 때문에 

```html
const arr = [1, 2, 3, 4, 5];

  return (
    <div className="App">
        <table>
          <tbody>
            {arr}  // 웹에 12345 가 표시됩니다.
          </tbody>
        </table>
    </div>
  );
```

이 방식을 응용하여 각 배열마다 테이블 요소인 **<tr></tr>을** 넣어주어 달력을 표현하겠습니다.

배열의 표현방식을 설명드렸으니 아래의 코드처럼 사용하면 테이블을 쉽게 만들 수 있습니다.

반복문을 사용하여 해당 달의 총주의 수만큼 반복문을 실행하고 테이블의 내용을 배열에 추가합니다.

```html
const calendarArr=()=>{

      let result = [];
      let week = firstWeek;
      for ( week; week <= lastWeek; week++) {
        result = result.concat(
          <tr key={week}>

          </tr>);
      }
      return result;
    }

  return (
    <div className="App">

        <div className="control">
          <button onClick={()=>{ setMoment(getMoment.clone().subtract(1, 'month')) }} >이전달</button>
          <span>{today.format('YYYY 년 MM 월')}</span>
          <button onClick={()=>{ setMoment(getMoment.clone().add(1, 'month')) }} >다음달</button>
        </div>
        <table>
          <tbody>
            {calendarArr()}
          </tbody>
        </table>
    </div>
  );
}
export default App;
```

**week** 가 설정됐으니 이제 **days**를 설정해줍니다. **week** 수만큼 7일 기준으로 반복문을 출력해주면 아래와 같이

출력될 것입니다.  **index**를 사용하여 각주의 시작 day마다 +0부터 +6까지 사용하여 표현하는 것이죠!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img_3.webp)

```html
<tr key={week}>
            {
              Array(7).fill(0).map((data, index) => {
                let days = today.clone().startOf('year').week(week).startOf('week').add(index, 'day');

                return(
                    <td key={index}  >
                      <span>{days.format('D')}</span>
                    </td>
                );

              })
            }
          </tr>
```

**\-중요한 부분 들어갑니다-**

원래 **moment()**는 **startOf('year')가** 없어도 현재 날짜를 기준으로 하기에 없어도 될 것 같지만 필요합니다!! 

저는 **moment()가** 현재 날짜로 초기화되어있다고 말씀드렸습니다.

저희가 위에서 설정한 53번째 주 같은 경우가 생기면  **moment()는** 1을 반환하기 때문에 53으로 바꿔주었습니다.

똑같이 **days**에서 사용한  **today** 변수도 이런 문제가 생길 수 있습니다.

53주째를 내년으로 출력하여 저희가 원하는 결과가 나오지 않을 수 있기 때문에 연도를 꼭 지정해주는 것입니다.

**거의 다 왔습니다.. 힘내세요!!!**

저희는 보통 달력을 볼 때 이번 달의 날짜가 아니어도 표현되는 부분이 있습니다. 

그리고 컴퓨터로 보는 달력이라면 오늘을 표현해주는 것은 당연한 것이겠지요 바로 코딩해줍니다.

```html
<tr key={week}>
            {
              Array(7).fill(0).map((data, index) => {
                let days = today.clone().startOf('year').week(week).startOf('week').add(index, 'day');

                if(moment().format('YYYYMMDD') === days.format('YYYYMMDD')){
                  return(
                      <td key={index} style={{backgroundColor:'red'}} >
                        <span>{days.format('D')}</span>
                      </td>
                  );
                }else if(days.format('MM') !== today.format('MM')){
                  return(
                      <td key={index} style={{backgroundColor:'gray'}} >
                        <span>{days.format('D')}</span>
                      </td>
                  );
                }else{
                  return(
                      <td key={index}  >
                        <span>{days.format('D')}</span>
                      </td>
                  );
                }
              })
            }
          </tr>
```

오늘이면 현재 날짜인 **moment(). format을** 사용하여 오늘이 맞으면 배경색을 **RED**

그달에 있는 날짜가 아니라면 **GRAY** 둘 다 아니라면 색이 없이 나오게 설정해주었습니다.

완성하셨다면 아래처럼 코드가 돼있을 것이고 css도 첨부하였습니다.

**App.js**

```html
import './App.css';
import {useState} from 'react';
import moment from 'moment';

const App =()=>{

  const [getMoment, setMoment]=useState(moment());

  const today = getMoment;
  const firstWeek = today.clone().startOf('month').week();
  const lastWeek = today.clone().endOf('month').week() === 1 ? 53 : today.clone().endOf('month').week();

    const calendarArr=()=>{

      let result = [];
      let week = firstWeek;
      for ( week; week <= lastWeek; week++) {
        result = result.concat(
          <tr key={week}>
            {
              Array(7).fill(0).map((data, index) => {
                let days = today.clone().startOf('year').week(week).startOf('week').add(index, 'day'); //d로해도되지만 직관성

                if(moment().format('YYYYMMDD') === days.format('YYYYMMDD')){
                  return(
                      <td key={index} style={{backgroundColor:'red'}} >
                        <span>{days.format('D')}</span>
                      </td>
                  );
                }else if(days.format('MM') !== today.format('MM')){
                  return(
                      <td key={index} style={{backgroundColor:'gray'}} >
                        <span>{days.format('D')}</span>
                      </td>
                  );
                }else{
                  return(
                      <td key={index}  >
                        <span>{days.format('D')}</span>
                      </td>
                  );
                }
              })
            }
          </tr>
        );
      }
      return result;
    }

  return (
    <div className="App">

        <div className="control">
          <button onClick={()=>{ setMoment(getMoment.clone().subtract(1, 'month')) }} >이전달</button>
          <span>{today.format('YYYY 년 MM 월')}</span>
          <button onClick={()=>{ setMoment(getMoment.clone().add(1, 'month')) }} >다음달</button>
        </div>
        <table>
          <tbody>
            {calendarArr()}
          </tbody>
        </table>
    </div>
  );
}
export default App;
```

**App.css**

```html
html, body {
  height: 100%;
}

 .App {
  height:100vh;
  width:100vw;
  font-size: 1.5vh;
  display: flex;      /* display 설정해줘야 아래 flex로 해주면 direction 선택가능*/
  flex-direction: column;   /* 이건 세로순으로  태그들을 표시함 css*/
  align-items: center;      /* 이건 가로 중앙 css*/
  justify-content: center;  /* 이건 세로 중앙 css*/

}

.App .control{
  display: flex;
  flex-direction: row;
}
.App table{
  display:flex;
  width:50vw;
  height:50vh;
}
.App table tbody{
  display:flex;
  flex-direction: column;
}
.App tr{
    display:flex;
    flex-direction: row;
}
.App td{
    display:flex;
    border:1px solid gray;
    width:5vw;
    height:5vh;
}
.App td span{
    display: flex;
    justify-content: flex-start;
    align-items: flex-start;
}
```

아래와 같은 화면이 잘 나오고 버튼도 잘 적용이 되셨나요?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/69/img_4.webp)

축하드립니다. **UI** 만 따로 코딩하시면 보다 예쁜 달력이 될 것이며 조금만 응용한다면

여러분만의 다양한 기능의 커스텀 달력을 만드실 수 있을 겁니다.   성실한 코딩 하세요!!
