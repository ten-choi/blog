---
title: "[코딩 테스트 - 스택/큐] 기능개발 in JS"
labels: ["CodingTest","프로그래머스","코딩테스트","코테"]
published: false
date: 2022-01-10T15:15:01+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 118
tistoryUrl: "https://yeolceo.tistory.com/118"
tistoryCategory: "CodingTest"
tistoryTags: ["프로그래머스","코딩테스트","코딩테스트","코테"]
tistoryPostedAt: "2022-01-10 15:15:01"
language: ko
bloggerPostId: "2107476554652624676"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/118/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/118/img_1.webp)

저의 풀이 및 설명입니다. 먼저 for문을 통해 index가 돌 때마다 speed를 추가해주었고 100 이상인 배포 가능한 index가 나왔을 때 개수를 체크하여 배포 가능한 개수만큼 result에 push 해줍니다.

한번 배포한 배열은 checked라는 배열에 push 하여 다음 반복문이 실행될 때 조건 처리에서 제외하는 방식입니다. 그리고 끝까지 반목 문이 완료되면 break 처리로 종료합니다.

```html
function solution(progresses, speeds) {

    let res=[]; //정답
    let checked = [];  //res에 넣은 추가된 배열
    while(1){ //무한.
    	//기존값에 추가되는값 추가 
        for(let i=0; i< progresses.length; i++){
            progresses[i] = progresses[i]+ speeds[i]
        }

        let num =0; //배포 개수 체크
        for(let j=0; j< progresses.length; j++){
            if(!checked.includes(j)){  // 배포한거는 체크에서 제외
                if(progresses[j]>=100){  // 100넘어간거 체크
                checked.push(j);  // 해당 index 넣기
                num+=1;  		// 배포개수에 +1 추가
                    if(j== progresses.length-1){  // 마지막에 else 안타기때문에 여기서 num추가
                        res.push(num);
                        break;
                    }
                }else{ //  배포 개수 정답에 넣고 for문 나오기
                    if(num)res.push(num); 
                    break;
                }
            }
        }
        if(checked.length == progresses.length)break; // 모든인덱스가 검색되면 종료
    }
    return res; //리턴
}
```

로직을 완성시키고 아래 코드와 같이 마지막 값을 넣어주는 부분 추가하면서 완성이 됐습니다. 

```html
if(j== progresses.length-1){
    res.push(num);
    break;
}
```

간단한 문제였고 저와 다른 풀이나 카테고리인 스택/큐 에 좀 더 가까운 사람이 있나 찾아봤습니다. 저와 비슷한 풀이에 간결함이 조금 더해진 코드들이 있었습니다. 아래의 다른 풀이법이 인상적이라 가져왔습니다.  

**\[ (100 - progress) /speeds \]**를 통한 maxDay 방식 풀이법입니다. 이런 방식을 생각해내고 만들었다는 게 신기했습니다.

가독성도 괜찮고 코드 자체가 간결한 느낌이 들어서 가져왔습니다.

```html
function solution(progresses, speeds) {
    let answer = [0];
    let days = progresses.map((progress, index) => Math.ceil((100 - progress) / speeds[index]));
    let maxDay = days[0];

    for(let i = 0, j = 0; i< days.length; i++){
        if(days[i] <= maxDay) {
            answer[j] += 1;
        } else {
            maxDay = days[i];
            answer[++j] = 1;
        }
    }

    return answer;
}
```

성실한 코딩 하세요.
