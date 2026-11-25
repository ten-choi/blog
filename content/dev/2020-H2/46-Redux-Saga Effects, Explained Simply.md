---
title: "Redux-Saga Effects, Explained Simply"
labels: ["TS","JS","react","Saga","Archive"]
published: true
date: 2020-09-10T18:13:44+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 46
tistoryUrl: "https://yeolceo.tistory.com/46"
tistoryCategory: "TS, JS/react"
tistoryTags: ["Saga","react","saga"]
tistoryPostedAt: "2020-09-10 18:13:44"
language: en
bloggerPostId: "734879331706390675"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/46/img.webp)

## **What Is Saga?**

In the React + Redux pattern, when Redux fetches data from the server, there's a delay until the server sends back a response.

So you need to wait out that delay and pass the value along once it arrives, handling it in order, and Saga takes care of that for you.

To really understand it, you'll want to be comfortable with JS generator syntax.

## **Saga Effects**

put: dispatches the action whose type you specify.

```html
ex -> Dispatches an action named CHECK.

  yield put({
        type:'CHECK',
        payload:response.data,
      });
```

delay: takes a duration and returns a promise that resolves once that time has passed.

```html
ex - With this, execution continues after 1000 milliseconds (1 second).

  yield deley(1000);
```

fork: called like a function, it runs its argument, but non-blocking (asynchronously).

```html
export function* Saga() {
    yield all([
        fork(func1()),
        fork(func2())    ]);
       };
```

call: called like a function, it runs its argument, but blocking (it waits for the result).

```html
export function* Saga() {
    yield all([
        call(func1()),
        call(func2())    ]);
       };
```

takeLatest: when the same action fires repeatedly, only the last one runs. If the REGISTER action is dispatched several times in a row,

                 only the last one is handled.

```html
export function* authSaga(){
  yield takeLatest(REGISTER , registerSaga);
}
```

takeEvery: handles every incoming action.

```html
export function* authSaga(){
  yield takeEvery(REGISTER , registerSaga);
}
```

all: pass an array to `all`, and the functions inside run concurrently; it completes once they've all resolved.

```html
export function* rootSaga(){
  yield all([authSaga() , userSaga() ]);
}
```

In practice, I mostly used `call` and `takeLatest` with Saga, since fetching server data while using Redux needs async handling.

Corrections are always welcome. Thanks!
