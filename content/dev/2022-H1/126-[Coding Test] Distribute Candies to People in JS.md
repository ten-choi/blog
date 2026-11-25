---
title: "[Coding Test] Distribute Candies to People in JS"
labels: ["CodingTest","leetcode","Distribute","Archive"]
published: true
date: 2022-02-20T15:45:10+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 126
tistoryUrl: "https://yeolceo.tistory.com/126"
tistoryCategory: "CodingTest"
tistoryTags: ["leetcode","코딩테스트","코테","Distribute"]
tistoryPostedAt: "2022-02-20 15:45:10"
language: en
bloggerPostId: "4992019454821673223"
---
#### Environment

JavaScript

#### Overview

Solving a coding test problem on LeetCode

#### Quick Summary of the Problem

1\. Hand out candies to people, giving 1, 2, ... N candies, one more each time.  
2\. If there are still candies left after the Nth person, start again from the first person.  
3\. If the candies run out while some people still haven't received any, fill their slots with 0.  
\-> See the English description below for details

We distribute some number of candies, to a row of **n = num\_people** people in the following way:

We then give 1 candy to the first person, 2 candies to the second person, and so on until we give n candies to the last person.

Then, we go back to the start of the row, giving n + 1 candies to the first person, n + 2 candies to the second person, and so on until we give 2 \* n candies to the last person.

This process repeats (with us giving one more candy each time, and moving to the start of the row after we reach the end) until we run out of candies.  The last person will receive all of our remaining candies (not necessarily one more than the previous gift).

Return an array (of length num\_people and sum candies) that represents the final distribution of candies.

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

    let res =[]   // holds the answer
    let i =0;     // index that keeps cycling through the people
    let cnt = 1;  // growing candy count
    let peopleCnt =1; // people count

    while(1){
    if(i ==num_people ) i = 0;  // reset once the last person has received candy

    if(candies-cnt <=0){   // not enough candies, or none left
        res[i] = (res[i]||0) + candies;   // existing amount + whatever is left
        candies = 0;   // mark that we're out of candies

        if(peopleCnt >= num_people)return res   // if people remain, keep looping to fill them with 0
    }else{
            // when there are enough candies
        res[i]= (res[i]||0) + cnt;  // add candies
        candies -= cnt;  // subtract from the remaining candies
    }

    peopleCnt ++;  // next person
    i++;    // advance the index
    cnt++;  // increase the candy count

    }
};
```

#### What I Could Have Done Better

1\. Without the parentheses, it assigns res\[i\] if res\[i\] exists, and otherwise assigns 0+cnt.  
What I actually meant (as in the final version) is: use 0 if there's no value yet, and add to the existing value if there is one.

```html
First ->	res[i]= res[i]||0+ cnt;
Final ->	res[i]= (res[i]||0) + cnt;
```

2\. If I had used the JS function **new Array(total array size).fill(initial value)**, I wouldn't have needed the || operation above.

#### git link

[https://github.com/ChoiYeol/Algorithm\_LeetCode/blob/main/1103-distribute-candies-to-people/1103-distribute-candies-to-people.js](https://github.com/ChoiYeol/Algorithm_LeetCode/blob/main/1103-distribute-candies-to-people/1103-distribute-candies-to-people.js)

Happy coding, and keep at it.
