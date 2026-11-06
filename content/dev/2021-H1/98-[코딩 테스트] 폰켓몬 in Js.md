---
title: "[코딩 테스트] 폰켓몬 in Js"
labels: ["CodingTest","코딩테스트","폰켓몬"]
published: true
date: 2021-05-22T17:13:53+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 98
tistoryUrl: "https://yeolceo.tistory.com/98"
tistoryCategory: "CodingTest"
tistoryTags: ["코딩테스트","폰켓몬"]
tistoryPostedAt: "2021-05-22 17:13:53"
language: ko
bloggerPostId: "6912782248161498416"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/98/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/98/img_1.webp)

더 간결할 수 있었지만 한 줄로 하고 싶어서 억지로 한 줄 만들기 했습니다. 

문제는 간단합니다.

N이 nums.length 즉 마릿수일때 

포켓몬을 N/2만큼 가져갈수있고 단 종류별로 하나씩이라서 3번 포켓몬이 3, 3, 3, 3 이렇게 4 마리 있으면 1마리만

가져갈 수 있는 시스템입니다.

즉 중복제거를해서 N/2 값보다 중복제거 값이 작으면 중복제거 값을 출력하고 아니면 N/2 값 출력하는 문제입니다. 

```html
function solution(nums) {

    return nums.length/2 < new Set(nums).length? 
    nums.length/2 : Array.from(new Set(nums)).length;
}
```

성실한 코딩하세요.
