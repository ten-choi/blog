---
title: "[코딩 테스트 - 동적계획법] N으로 표현 in Js"
labels: ["CodingTest","코딩테스트","N으로"]
published: true
date: 2021-05-22T17:07:37+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 97
tistoryUrl: "https://yeolceo.tistory.com/97"
tistoryCategory: "CodingTest"
tistoryTags: ["코딩테스트","N으로"]
tistoryPostedAt: "2021-05-22 17:07:37"
language: ko
bloggerPostId: "8719183697193588770"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/97/img.webp)

N으로 표현입니다.

중복을 제거하는 배열 8개를 set으로 만들어줍니다.

문제에선 N을 8번까지 사용합니다. 그래서 선언하면서 미리 N값을 넣어주는 작업이 필요합니다.

왜냐하면 연산 이외의 n을 사용하는 법이 예를 들어 5가 있으면 55, 555, 5555 같은 개념이 연산 없이 5라는 숫자를 

사용하는 법이기 때문에 미리 넣어줍니다.

이후에는 이중 반복문을 통해 값을 구합니다.

N을 1번쓴경우

I와 J값이 0, 0 일 때는 for문이 돌지 않기 때문에 arr \[i\]을 검사합니다. -> arr \[0\] 처음에 5를 하나 넣어줬습니다.

set의 함수 has를 통해 검사합니다. 

N을 2번 쓴 경우

I값이 올라갈 때부터 for문이 돌아갑니다. arr \[0\] arr \[0\] 이렇게 두 개가 사칙연산을 하면서 arr \[1\]을 채웁니다.

그럼 N2번써서 생긴 사칙연산과 기존에 55 넣어준 값이 있으니까 55, 5+5, 5-5, 5\*5, 5/5 이런 값들이 들어갑니다.

그럼 또 number값이 arr \[1\] 중에 있나 비교합니다.

N을 3번 쓴 경우 

동일한데 이제 555 있는 arr \[2\] 항에다가  N을 한번 쓴 arr \[0\]과 N을 두 번 쓴 arr \[1\] 자릿수를 비교합니다.

arr \[2\]는 555, 55+5, 55-5, 55\*5, 55/5... 5/55  등의 숫자가 들어갑니다. 중복을 제거하면서 

음수나 분수 개념 되는 부분은 어차피 number값이 정수만 나오니까 그냥 뒀습니다.

이렇게 N4 N5 진행하고 8번넘어가면 -1 리턴했습니다. 

```html
function solution(N, number) {

    const arr = new Array(8).fill().map((v,i) => new Set(
        [parseInt(N.toString().repeat(i+1))]
    ));
    // const arr = new Array(8).fill(new Set());  바로 채우면 시간지연 오류
    //const arr = new Array(8).fill().map(()=>new Set()); map쓰면 오류안남 why
    for(let i=0; i<8; i++){
        // arr[i].add(parseInt(N.toString().repeat(i+1)));
        for(let j=0; j<i; j++){
            for(let item1 of arr[j]){
                for(let item2 of arr[i-j-1]){
                arr[i].add(item1+item2); 
                arr[i].add(item1-item2);
                arr[i].add(item1*item2);
                arr[i].add(item1/item2);
                }                
            }
        }
        if(arr[i].has(number)){
            return i+1;
        }
    }
    return -1;
}
```

코드 중에 주석 부분을 사용해서 new Set()을 fill안에 바로 넣어주면 에러 뜨더군요.. 저에게 지식을 나눠주시면 감사합니다.

성실한 코딩 하세요
