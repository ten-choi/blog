---
title: "[ Node ] Node 이벤트 루프란"
labels: ["TS","JS","nodejs","JavaScript","node","EventLoop","libuv"]
published: false
date: 2022-04-07T12:14:45+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 130
tistoryUrl: "https://yeolceo.tistory.com/130"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["JavaScript","node","nodejs","EventLoop","libuv"]
tistoryPostedAt: "2022-04-07 12:14:45"
language: ko
bloggerPostId: "6185108960706734847"
---
#### 개요

Node 개발을 하며 **[Node이벤트 루프에](https://nodejs.org/ko/docs/guides/event-loop-timers-and-nexttick/)** 대해 알아봅니다. 공식문서의 글을 많이 참조했습니다.  
javascript eventloop를 모른다면 이분 영상이 괜찮으니까 보면 좋습니다. **[링크 참조](https://www.youtube.com/watch?v=QFHyPInNhbo&ab_channel=%EC%9A%B0%EB%A6%AC%EB%B0%8B_woorimIT)**

#### 목차

-   Node 란
-   Node Event Loop 기본
-   Node Event Loop 심화

## **\- Node 란**

Node는 Chrome V8JavaScript 엔진으로 빌드된 JavaScript 런타임입니다.

Single-Thread이며 non-blocking I/O 이벤트 기반 비동기 방식으로 동작합니다.

## **\- Node Event Loop 기본**

JavaScript가 싱글 스레드이지만 Node의 이벤트 루프는 가능하다면 언제나 시스템 커널에 작업을 떠넘겨서 Node.js가 논 블로킹 I/O 작업을 수행하도록 해줍니다.

대부분의 현대 커널은 멀티 스레드이므로 백그라운드에서 다수의 작업을 실행할 수 있습니다. 이러한 작업 중 하나가 완료되면 커널이 Node.js에게 알려주어 적절한 콜백을 **poll** 큐에 추가할 수 있게 하여 결국 실행되게 합니다. 

![https://nodejs.org/ko/docs/guides/event-loop-timers-and-nexttick/  (Node 공식사이트 이미지 참조)](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/130/img.webp)

## 단계 개요

-   **timers**: 이 단계는 setTimeout()과 setInterval()로 스케줄링한 콜백을 실행합니다.
-   **pending callbacks**: 다음 루프 반복으로 연기된 I/O 콜백들을 실행합니다.
-   **idle, prepare**: 내부용으로만 사용합니다.
-   **poll**: 새로운 I/O 이벤트를 가져옵니다. I/O와 연관된 콜백(클로즈 콜백, 타이머로 스케줄링된 콜백, setImmediate()를 제외한 거의 모든 콜백)을 실행합니다. 적절한 시기에 node는 여기서 블록 합니다.
-   **check**: setImmediate() 콜백은 여기서 호출됩니다.
-   **close callbacks**: 일부 close 콜백들, 예를 들어 socket.on('close',...).

이벤트 루프가 실행하는 사이 Node.js는 다른 비동기 I/O나 타이머를 기다리고 있는지 확인하고 기다리고 있는 것이 없다면 깔끔하게 종료합니다.

## **\- Node Event Loop 심화**

1\. timers

타이머는 정확한 시간이 아닌 제공된 콜백으로 시간을 지정하고 그 뒤에 스케줄링된다고 합니다.  
예를 들어 1초 뒤 실행의 타이머가 있을 때 0.95초짜리 콜백을 실행하고 그 뒤에 타이머를 실행하는 방식입니다.  
0.1초 실행시간이 걸리는 타이머일 경우 1.05 초에 실행될 것입니다. 약간 부정확하기도 하단 의미입니다.  
timers 단계는 지정시간이 지나면 가장 빠르게 실행되며 만약 poll 단계에서 모든 리소스를 차지할 경우 timers 단계에 영향이 가기 때문에 poll 제어를 libuv에서 해준다고 합니다.

2\. pending callbacks: 이 단계에서는 TCP 오류 같은 시스템 작업의 콜백을 실행합니다. 예를 들어 TCP 소켓이 연결을 시도하다가 ECONNREFUSED를 받으면 일부 \*nix 시스템은 오류를 보고하기를 기다리려고 합니다. 이는 **pending callbacks** 단계에서 실행되기 위해 큐에 추가될 것입니다 - 공식문서

위와 같은 TCP의 영역과 다르게 루프의 반복으로 연기된 I/O가 완료되면 결과가 큐에 담깁니다. 예를 들면 파일의 Read, Write 작업이 완료된 후 콜백이나 네트워크 작업 등이 완료된 경우 pending callbacks으로 간다는 글 [참조](https://nexocode.com/blog/posts/behind-nodejs-event-loop/)입니다. Js Event Loop의 WebApi에서 큐로 가는 과정과 유사한 처리가 일어난다고 생각됩니다.

3\. idle, prepare: 내부용으로만 사용한다고 하니 생략합니다.

4\. poll: 새로운 I/O이벤트를 가져옵니다. I/O와 연관된 콜백을 실행합니다. 

**poll** 단계는 두 가지 주요 기능을 가집니다.

1.  I/O를 얼마나 오래 블록하고 폴링 해야 하는지 계산합니다. 그다음
2.  **poll** 큐에 있는 이벤트를 처리합니다.

이벤트 루프가 **poll** 단계에 진입하고 스케줄링된 타이머가 없을 때 두 가지 중 하나의 상황이 발생합니다.

-   **poll** 큐가 **비어있지 않다면** 이벤트 루프가 콜백의 큐를 순회하면서 큐를 다 소진하거나 시스템 의존적인 하드 한계에 도달할 때까지 동기로 콜백을 실행합니다.

-   **poll** 큐가 **비어있다면** 다음 중 하나의 상황이 발생합니다.
    -   스크립트가 setImmediate()로 스케줄링되었다면 이벤트 루프는 **poll** 단계를 종료하고 스케줄링된 스크립트를 실행하기 위해 **check** 단계로 넘어갑니다.
    -   스크립트가 setImmediate()로 스케줄링되지 않았다면 이벤트 루프는 콜백이 큐에 추가되기를 기다린 후 즉시 실행합니다.

js의 callStack처럼 callback 함수가 스택으로 쌓여있을 경우 끝까지 poll을 실행합니다.  
**poll** 큐가 일단 비게 되면 타이머가 시간 임계점에 도달했는지 확인할 것입니다. 하나 이상의 타이머가 준비되었다면 이벤트 루프는 타이머의 콜백을 실행하기 위해 **timers** 단계로 돌아갈 것입니다.

5\. check: setimmediate() 콜백은 여기서 호출됩니다. 앞의 순서를 거치면 check 페이즈가 실행되는데 원래 timers 가 먼저 실행되는 게 맞지만 node에서 

만약 두 함수 모두 메인 모두에서 호출되었다면, 타이밍은 **프로세스 성능에 의해 결정**된다. 예를 들어 만약 다음과 같은 스크립트를 실행한다면 두 타이머의 실행 순서는 딱 정해지지 않는다. \- [참조](https://velog.io/@adam2/Node.js-%ED%95%B4%EB%B6%80%ED%95%99-2-%EC%9D%B4%EB%B2%A4%ED%8A%B8-%EB%A3%A8%ED%94%84-phase)

```html
setTimeout(function() {
    console.log('setTimeout')
}, 0);
setImmediate(function() {
    console.log('setImmediate')
});
```

6\. close callbacks: 일부 close 콜백들 이벤트 루프가 실행하는 사이 Node.js 는 다른 비동기나 I/O나 타이머를 가지고  
있는지 확인하고 없다면 깔끔하게 종료합니다.

각 페이즈가 끝날 때마다 nextTickQueue, microTaskQueue 가 실행됩니다

node.js 문서에 따르면 "nextTickQueue는 이벤트 루프의 현재 단계에 관계없이 현재 작업이 완료된 후 처리됩니다." 이렇게 명시되어있습니다

타이머 페이즈 부분은 node 11 버전 미만일 때 같은 js 런타임인 브라우저와는 동작 방식이 달랐는데 다시 똑같아졌다고 합니다. - [참조](https://blog.insiderattack.net/new-changes-to-timers-and-microtasks-from-node-v11-0-0-and-above-68d112743eb3)

nextTickQueue에 event callback들이 적재된다.

microTaskQueue에 promise가 적재된다. 

idle, prepare는 문서에서도 크게 다루지 않아 생략합니다.

실행하면서 테스트해보아요.

```html
setImmediate(() => console.log('this is set immediate 1'));
setImmediate(() => console.log('this is set immediate 2'));
setImmediate(() => console.log('this is set immediate 3'));

setTimeout(() => console.log('this is set timeout 1'), 0);
setTimeout(() => {
    console.log('this is set timeout 2');
    process.nextTick(() => console.log('this is process.nextTick added inside setTimeout'));
}, 0);
setTimeout(() => console.log('this is set timeout 3'), 0);
setTimeout(() => console.log('this is set timeout 4'), 0);
setTimeout(() => console.log('this is set timeout 5'), 0);

process.nextTick(() => console.log('this is process.nextTick 1'));
process.nextTick(() => {
    process.nextTick(console.log.bind(console, 'this is the inner next tick inside next tick'));
});
process.nextTick(() => console.log('this is process.nextTick 2'));
process.nextTick(() => console.log('this is process.nextTick 3'));
process.nextTick(() => console.log('this is process.nextTick 4'));

function callBack1(){ console.log('this is function 1')}
function callBack2(){ 
    console.log('this is function 2')
    callBack4();
    process.nextTick(() => console.log('this is function 2 of process.nextTick 1'));
}
function callBack3(){ console.log('this is function 3')}
function callBack4(){ console.log('this is function 4')}

callBack1()
callBack2()
callBack3()
```

javascript의 이벤트 루프에서 CallStack이 Poll과 유사하며 비동기 처리를 하기 위해 Node가 조금 더 분류되어있는 구조라고 생각하면 쉽게 이해할 수 있습니다. 

공식문서가 깔끔하게 설명돼있어서 큰 이견이 없어 복붙 한 부분이 많습니다. 

공문 참조하시고 JS Event Loop 알아보면 좋고 모자라면 **[이분 글](https://www.korecmblog.com/node-js-event-loop/)** 도움이 될듯합니다.

근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.
