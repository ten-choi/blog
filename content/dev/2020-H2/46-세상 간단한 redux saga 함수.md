---
title: "세상 간단한 redux saga 함수"
labels: ["TS","JS","react","Saga"]
published: false
date: 2020-09-10T18:13:44+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 46
tistoryUrl: "https://yeolceo.tistory.com/46"
tistoryCategory: "TS, JS/react"
tistoryTags: ["Saga","react","saga"]
tistoryPostedAt: "2020-09-10 18:13:44"
language: ko
bloggerPostId: "734879331706390675"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/46/img.webp)

## **Saga란**

react redux 패턴에서 redux가 서버값을 가져오는 부분을 실행하면 서버는 값을 토해낼 때까지 지연이 생깁니다.

그래서 그지 연을 기다렸다가 값을 받으면 전달하게끔 동기 처리를 해야 하는데 그 행위를 saga가 대신해줍니다.

능통한 이해를 위해선 js의 generator 문법을 숙지할 필요가 있습니다.

## **Saga 함수 목록**

put : type에 선언된 action을 dispatch 합니다. 

```html
ex ->CHECK 라는 이름을 가진 action을 dispatch 합니다.

  yield put({
        type:'CHECK',
        payload:response.data,
      });
```

delay : 시간을 설정하고 시간이 지나면 resolve를 실행하는 promise 객체를 반환합니다.

```html
ex - 이렇게하면 해당 실행이 1000 밀리세컨(1초) 뒤에 시작됩니다.

  yield deley(1000);
```

fork :  함수 형태로 사용하여 fork함수의 인자를 실행하지만 비동기 처리입니다.

```html
export function* Saga() {
    yield all([
        fork(func1()),
        fork(func2())    ]);
       };
```

call :함수 형태로 사용하여 call함수의 인자를 실행하지만 동기 처리입니다. 

```html
export function* Saga() {
    yield all([
        call(func1()),
        call(func2())    ]);
       };
```

takeLatest :  동일한 명령이 막 겹치면 마지막 것만 실행합니다. REGISTER 액션을 여러 번 겹쳐서 수행하면

                 마지막 것만 실행합니다.

```html
export function* authSaga(){
  yield takeLatest(REGISTER , registerSaga);
}
```

takeEvery : 들어오는 모든 액션 명령을 전부 처리합니다. 

```html
export function* authSaga(){
  yield takeEvery(REGISTER , registerSaga);
}
```

all : all함수를 사용하여 배열에 인자로 넣어주면 내부 함수들이 동시에 실행되고 전부 resolve 될 때 완료 처리됩니다. 

```html
export function* rootSaga(){
  yield all([authSaga() , userSaga() ]);
}
```

saga에서 사용하는 건 대부분 call과 teakLeast 였습니다. redux사용 중 서버값 가져올 때 비동기 처리해야 하니까요.

지적은 언제든 환영입니다. 감사합니다.
