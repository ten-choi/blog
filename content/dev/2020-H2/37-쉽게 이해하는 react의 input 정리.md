---
title: "쉽게 이해하는 react의 input 정리"
labels: ["TS","JS","react","input"]
published: false
date: 2020-08-10T13:24:27+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 37
tistoryUrl: "https://yeolceo.tistory.com/37"
tistoryCategory: "TS, JS/react"
tistoryTags: ["input","react","input"]
tistoryPostedAt: "2020-08-10 13:24:27"
language: ko
bloggerPostId: "8692634725354448682"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/37/img.webp)

## **\-input이란**

      키보드 입력을 가능하게 해 주는 html 태그

## **\-JSX에서의 사용법**

input의 값을 변경하고 변경값을 알기 위해서는 절차가 필요합니다. 

그중에서 아래와 같은 경우는 input의 e.target.value로 입력한 값을 받아주는 동시에

handleChange를 통해 state값을 이용하여 입력받은 값을 value 값에 대입하고 setState를 통해

바로 변경해주는 코드입니다. 

```html
import React  from 'react'

export default class App extends React.Component {
  state = {
    value:''
  }
  handleChange = (e) => {
    this.setState({
      value: e.target.value
    });
  }
  render() {
    return (
        <>
        <input
          placeholder="input start"
          value={this.state.value}
          onChange={this.handleChange}
        />
      <div>{this.state.value}</div>
        </>
    );
  }
}
```

이부분은 아주 간단하지만 1:1 대응입니다. 즉 input이 여러 개면

value1 value2를 해줘야 할 수도 있습니다. 하지만 그렇게 하면 너무 불편합니다.

그래서 하나의 코드로 n대응이 가능하게도 할 수 있습니다. 

```html
import React  from 'react'

export default class App extends React.Component {
  state = {
    name1: '',
   	name2: ''
  }
  handleChange = (e) => {
    this.setState({
      [e.target.name]: e.target.value
    });
  }
  render() {
    return (
	<>
        <input
          placeholder="name1"
          value={this.state.name1}
          onChange={this.handleChange}
          name="name1"
        />
        <input
          placeholder="name2"
          value={this.state.name2}
          onChange={this.handleChange}
          name="name2"
        />
        <div>{this.state.name1} {this.state.name2}</div>
    </>
    );
  }
}
```

key를 \[ \]로 감싸면 그 안에 넣은 레퍼런스가 가리키는 실제 값이 key 값으로 사용됩니다.

요문구가 react 책에 있습니다. 

Key는 React가 어떤 항목을 변경, 추가 또는 삭제할지 식별하는 것을 돕습니다. key는 엘리먼트에 안정적인 고유성을 부여하기 위해 배열 내부의 엘리먼트에 지정해야 합니다.

요런 문구가 react공식문서 사이트에 있더라고요 (map 때문에 있던 문장 같지만...)

e.target이나 e 가 어떤 항목을 변경, 추가 또는 삭제할지 식별하는 것을 돕는 키라고 생각하면

설명이 들어맞습니다. \[\]로 감싸면 key로 가져온 값 부분 입력받는 부분이 아닌 해당 태그에 

value값 자체를 가리키는 것이죠. 아주 상세한 부분이 결여돼있을 수 있지만 개념은 이렇습니다. 

쉽고 편하게 이해하셨길 바랍니다.
