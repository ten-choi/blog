---
title: "[코딩 테스트] 문자열 압축 in Js"
labels: ["CodingTest","코딩테스트","문자열"]
published: false
date: 2021-06-02T17:54:18+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 101
tistoryUrl: "https://yeolceo.tistory.com/101"
tistoryCategory: "CodingTest"
tistoryTags: ["코딩테스트","문자열"]
tistoryPostedAt: "2021-06-02 17:54:18"
language: ko
bloggerPostId: "2862640407958355640"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/101/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/101/img_1.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/101/img_2.webp)

문자열 압축 문제입니다.

'aabccc'를 예로 들면 1개 기준으로 압축할 경우 '2 ab3 c'가 됩니다. 3개 이상부터 문자열이 숫자와 문자열이 되면서

길이가 감소되는 효과를 봅니다. 2개 기준으로 압축한다면 'ababcccc' 의경우 '2ab2cc' 고됩니다.

이런 식으로 3개, 4개 5개..  string.length 길이에 맞춰서 문자열을 압축하고 최소 길이를 리턴하면 됩니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/101/img_3.webp)

위에처럼 안되니까 주의하세요.

풀이 설명 들어갑니다. 코드를 봐주세요.

```html
function solution(s) { 
    let resArr = new Set();  // 사이즈별 압축했을때의 문자열 길이를 담는 배열 

    for (var i=1; i<=s.length; i++) {  //1개씩 잘라서 문자열 비교를 시작하기때문에 i=1;

        let count = 1;              // 중복문자열의 갯수 새는 변수
        let addStr = '';            // 압축된 문자열 변수

        for (var j=0; j<s.length; j=j+i) { // 0에서 i만큼 더하는 포문

            var curSub = s.slice(j, j+i);      //0부터 시작하는 i의 배수 
            var nextSub = s.slice(j+i, j+i+i); // i부터 시작하는 i의 배수

            if( curSub == nextSub) { // 현재 문자열과 다음 문자열을 비교
                count += 1;    // 같으면 중복이니까 count를 추가
            } else { // 다를경우
                if(count != 1){  // count가 1이 아니면 중복이 있었다는 의미기때문에
                				// 현재값 + 숫자+ 문자열 을 해줍니다. 
                     addStr = addStr + count + curSub;
                } else { // 1이라면 중복이 없기때문에 현재값 + 문자열 해주시면 됩니다.
                     addStr = addStr + curSub;
                }
                count = 1; count 는 for문이 새로돌기전에 초기화 해줍니다.
            }
        }
        resArr.add(addStr.length); //i 사이즈별 문자열 압축 length를 추가합니다.
    }
    return Math.min(...resArr); 최솟값을 반환합니다.
}
```

i사이즈의 압축을 통한 최솟값 반환 문제였습니다. 성실한 코딩 하세요.
