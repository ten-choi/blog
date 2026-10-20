---
title: "js 문법과es6에 대해 알아본 점"
labels: ["TS","JS","javascript","ES6"]
published: false
date: 2020-08-12T15:08:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 39
tistoryUrl: "https://yeolceo.tistory.com/39"
tistoryCategory: "TS, JS/javascript"
tistoryTags: ["ES6","js"]
tistoryPostedAt: "2020-08-12 15:08:11"
language: ko
bloggerPostId: "2440555935271716949"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/39/img.webp)

**ECMA스크립트**(ECMAScript, 또는 ES[\[1\]](https://ko.wikipedia.org/wiki/ECMA%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8#cite_note-1))는 [Ecma 인터내셔널](https://ko.wikipedia.org/wiki/Ecma_%EC%9D%B8%ED%84%B0%EB%82%B4%EC%85%94%EB%84%90)의 **ECMA-262** 기술 규격에 정의된 표준화된 [스크립트 프로그래밍 언어](https://ko.wikipedia.org/wiki/%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8_%ED%94%84%EB%A1%9C%EA%B7%B8%EB%9E%98%EB%B0%8D_%EC%96%B8%EC%96%B4)이다. [자바스크립트](https://ko.wikipedia.org/wiki/%EC%9E%90%EB%B0%94%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8)를 표준화하기 위해 만들어졌고 지금도 자바스크립트가 제일 잘 알려져 있지만, [액션스크립트](https://ko.wikipedia.org/wiki/%EC%95%A1%EC%85%98%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8)와 [J스크립트](https://ko.wikipedia.org/wiki/J%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8) 등 다른 구현체도 포함하고 있다.[\[2\]](https://ko.wikipedia.org/wiki/ECMA%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8#cite_note-2) ECMA스크립트는 [웹](https://ko.wikipedia.org/wiki/%EC%9B%94%EB%93%9C_%EC%99%80%EC%9D%B4%EB%93%9C_%EC%9B%B9)의 클라이언트 사이드 스크립트로 많이 사용되며 [Node.js](https://ko.wikipedia.org/wiki/Node.js)를 사용한 서버 응용 프로그램 및 서비스에도 점차 많이 쓰이고 있다.

라고 나무위키에서 말한다.

참고로 es2015가 es6고 es5는 그밑이다. js에서 연도별로 저렇게 밀어간다고 한다. (2016이면 es7)

es6가되면서 \`(백틱)사용이 가능하게됬다고한다. 필자는 구분없이 그냥 사용했다.

var만 있던게 const let이 생겨서 스코프가 생긴건 유명하다.

```html
var object = {                           |     const object6 = {

  name : name ,                          |             name,

  age : age                              |             age ,

                                         |     ['es'+6]: '지금은 이렇게 내부에서 속성명 선언해도됌'

}                                        |     }

object['es'+5] = '예전엔이렇게 따로선언';  |
```

es6가 오른쪽것이다. 선언할 변수와 입력할 변수의 이름이 같은 경우에 오른쪽처럼 사용가능하다고한다.

화살표함수(es6)는 this를 호출한곳에서 결정하게 하기위해 쓴다. bind안쓰려고 씀. 일단 유명한건 이쯤적는다.

코드 밑으로 몇개 MDN에서 가져옴 설명하자면 js의 객체구조인데 

var \[a, ...b\] \= \[1, 2, 3\];

console.log(a);console.log(b);  //값   1          23     이렇게가 가능함

var o \= {p: 42, q: true};

var {p, q} \= o; console.log(p);

// 42 console.log(q); // true 

 1.  var a, b;           ({a, b} \= {a: 1, b: 2}); 이건됨

 2. var a, b;        {a, b} \= {a: 1, b: 2} ; 이건안됨  좌변이 객체가 아니라 블록으로 간주된다고함 

**참고**: 할당 문을 둘러싼 ( .. )는 선언 없이 객체 리터럴(object literal) 비구조화 할당을 사용할 때 필요한 구문입니다.  
라고 명시되어있음 즉    괄호로 구문을 짜게되면 블록이아닌 객체 리터럴로 인정해준다는 말임

js를 책이 아닌 검색이나 강좌로 배운사람에겐 객체에 관한 지식이 꽤 도움이 될듯하다. 

[https://developer.mozilla.org/ko/docs/Web/JavaScript/Reference/Operators/Destructuring\_assignment](https://developer.mozilla.org/ko/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment)
