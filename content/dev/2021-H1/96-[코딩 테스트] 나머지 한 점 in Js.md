---
title: "[코딩 테스트] 나머지 한 점 in Js"
labels: ["CodingTest","코딩테스트","나머지"]
published: true
date: 2021-05-22T16:53:06+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 96
tistoryUrl: "https://yeolceo.tistory.com/96"
tistoryCategory: "CodingTest"
tistoryTags: ["코딩테스트","나머지"]
tistoryPostedAt: "2021-05-22 16:53:06"
language: ko
bloggerPostId: "8033083875057385672"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/96/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/96/img_1.webp)

규칙을 찾았습니다.

첫항에 같은 숫자가 2개 들어가는 것과 1개 들어가는 것 두 번째 항도 동일한 개념입니다.

첫 번째 예를 기준으로 배열에서 \[0\] 부분은 1, 3, 3 이면 3이 겹치는 상태입니다.

배열에서 \[1\] 부분은 4, 4, 10 이면 4가 겹치는 상태입니다. 겹치는 부분을 소거해주면 하나의 좌표가 나옵니다.

\[1, 10\] result 값입니다. 이런 식으로 저는 답을 찾았습니다.

```html
function solution(v) {
    let arr1=new Set(), arr2=new Set();   // set은 그냥 array 비슷한 개념인데 es6 익숙해지려고 썼습니다. (여러분도 써보세요)
    for(let i of v){
        arr1.has(i[0])?arr1.delete(i[0]):arr1.add(i[0]);   // 여기서 숫자가 같은 숫자가 있으면 제거해줍니다. 0번 항
        arr2.has(i[1])?arr2.delete(i[1]):arr2.add(i[1]);   // 여기서 숫자가 같은 숫자가 있으면 제거해줍니다. 1번 항
    }
    return [...arr1, ...arr2]; // spread 연산자를 써줘서 배열 안에 각 숫자를 담아줍니다.
}
```

어떤 분은 저와 같은 개념이지만 식을 ^= (비트 연산)으로 만드셨습니다. 제기준엔 비트 연산이 제일 효율적인 코드였습니다.

제 코드는 비트 연산을 나열한 코드고요.  읽어주셔서 감사합니다 성실한 코딩 하세요.
