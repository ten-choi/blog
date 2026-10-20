---
title: "[코딩 테스트 - 탐욕법] 체육복 in Js"
labels: ["CodingTest","체육복","코딩테스트"]
published: false
date: 2021-05-22T17:22:17+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 99
tistoryUrl: "https://yeolceo.tistory.com/99"
tistoryCategory: "CodingTest"
tistoryTags: ["체육복","코딩테스트"]
tistoryPostedAt: "2021-05-22 17:22:17"
language: ko
bloggerPostId: "4886346461160370838"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/99/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/99/img_1.webp)

문제는 첫 번째 예를 기준으로 설명하자면

n명중에 체육복 없는 애가 lost, 있는 애가 나머지 아이들 , 2벌 가진 사람이 reserve입니다. 

그런데 reserve와 lost에 둘다 호명돼 있는 경우 1벌로 칩니다. 그리고 2벌인 경우는 자기 번호 +1, -1 거리로 만 빌려줄 수 있습니다.

그래서 첫 번째 for문에서 lost와 reserve에 다 포함되어있는지 체크해주었습니다.

두 번째 for문에서 +1과 -1 비교로 남은 아이의 체육복을 없는 친구에게 주었습니다.

\-1을 넣은 이유는 배열 최댓값에 관여하지 않기 위해서입니다. 좀 더 깔끔하게 푸신분들도 있으니까 

프로그래머스의 풀이를 참조하는 것도 좋을듯합니다.

```html
function solution(n, lost, reserve) {

    for (let i = 0; i < lost.length; i++) {
        let overL = reserve.indexOf(lost[i]);
        if (overL >=0) {
            lost.splice(i,1, -1);
            reserve.splice(overL,1, -1);
        }
    }
    for(let i=0; i< lost.length; i++) {
        for(let j=0; j< reserve.length; j++) {
            if(reserve[j]-1==lost[i] || reserve[j]+1==lost[i]){
                lost.splice(i,1, -1);
                reserve.splice(j,1, -1);
                break;

            }
        }      
    }
    return n -  lost.filter(arr => arr!= -1).length;

}
```

그리고 -1 필터로 제거하고 배열 값 뽑아줘서 체육 복가진 사람 인원수를 구해주었습니다.

성실한 코딩 하세요.
