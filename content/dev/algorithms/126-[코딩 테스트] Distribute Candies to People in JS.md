---
title: "[코딩 테스트] Distribute Candies to People in JS"
labels: ["CodingTest","leetcode","코딩테스트","코테","Distribute"]
published: false
date: 2022-02-20T15:45:10+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 126
tistoryUrl: "https://yeolceo.tistory.com/126"
tistoryCategory: "CodingTest"
tistoryTags: ["leetcode","코딩테스트","코테","Distribute"]
tistoryPostedAt: "2022-02-20 15:45:10"
language: ko
bloggerPostId: "4992019454821673223"
---
#### 환경 

JavaScript

#### 개요

LeetCode에서 코테하기 

#### 문제 간단 요약

1\. 사람들에게 사탕이 N 개라면 을 1~N개까지 계속 +1 씩 해서 나눠줍니다.  
2\. N명 까지 나눠주었는데 사탕이 남았다면 처음 사람에게 또다시 나눠줍니다.  
3\. 사탕이 다 떨어졌어도 받을 인원이 남았다면 0으로 채워줘야 합니다.  
\-> 추가 설명은 영문 참조

We distribute some number of candies, to a row of **n = num\_people** people in the following way:

We then give 1 candy to the first person, 2 candies to the second person, and so on until we give n candies to the last person.

Then, we go back to the start of the row, giving n + 1 candies to the first person, n + 2 candies to the second person, and so on until we give 2 \* n candies to the last person.

This process repeats (with us giving one more candy each time, and moving to the start of the row after we reach the end) until we run out of candies.  The last person will receive all of our remaining candies (not necessarily one more than the previous gift).

Return an array (of length num\_people and sum candies) that represents the final distribution of candies.

**Example 1:**

```smali
Input: candies = 7, num_people = 4
Output: [1,2,3,1]
Explanation:
On the first turn, ans[0] += 1, and the array is [1,0,0,0].
On the second turn, ans[1] += 2, and the array is [1,2,0,0].
On the third turn, ans[2] += 3, and the array is [1,2,3,0].
On the fourth turn, ans[3] += 1 (because there is only one candy left), and the final array is [1,2,3,1].
```

**Example 2:**

```smali
Input: candies = 10, num_people = 3
Output: [5,2,3]
Explanation: 
On the first turn, ans[0] += 1, and the array is [1,0,0].
On the second turn, ans[1] += 2, and the array is [1,2,0].
On the third turn, ans[2] += 3, and the array is [1,2,3].
On the fourth turn, ans[0] += 4, and the final array is [5,2,3].
```

**Constraints:**

-   1 <= candies <= 10^9
-   1 <= num\_people <= 1000

```html
var distributeCandies = function(candies, num_people) {

    let res =[]   //정답넣을곳
    let i =0;     //사람 명수만큼 계속 돌아야하는 인덱스
    let cnt = 1;  //늘어나는 캔디수 카운트
    let peopleCnt =1; //사람수 카운트

    while(1){
    if(i ==num_people ) i = 0;  // 마지막 사람까지 캔디를 줬을때 초기화

    if(candies-cnt <=0){   // 캔디 수가 모자라거나 없을때
        res[i] = (res[i]||0) + candies;   // 기존수 + 남은양 
        candies = 0;   // 이제 캔디없다고 표시

        if(peopleCnt >= num_people)return res   //사람이 남았다면 계속 돌려서 0넣어주는 조건문
    }else{
            // 캔디 여유있을때 
        res[i]= (res[i]||0) + cnt;  // 캔디 추가  
        candies -= cnt;  //기존 부여받은 캔디에서 까주기
    }

    peopleCnt ++;  //다음 인원
    i++;    // 인덱스 추가
    cnt++;  // 캔디 카운트 추가

    }
};
```

#### 아쉬웠던 부분

1\. 괄호가 없으면 res \[i\]가 존재하면 res \[i\]를 넣어주고 아니면 0+cnt를 넣어줍니다.  
의도는 최종처럼 값이 없으면 0을 넣어주고 계산하고 있으면 있는 걸 계산하는 의도입니다.

```html
처음 ->	res[i]= res[i]||0+ cnt;
최종 ->	res[i]= (res[i]||0) + cnt;
```

2\. Js 함수중 하나인 **new Array(배열 총 크기). fill(초기화할 숫자)** 이 함수를 사용했다면 위와 같은 || 연산을 안 해도 됐습니다.

#### git link

[https://github.com/ChoiYeol/Algorithm\_LeetCode/blob/main/1103-distribute-candies-to-people/1103-distribute-candies-to-people.js](https://github.com/ChoiYeol/Algorithm_LeetCode/blob/main/1103-distribute-candies-to-people/1103-distribute-candies-to-people.js)

성실한 코딩 하세요.
