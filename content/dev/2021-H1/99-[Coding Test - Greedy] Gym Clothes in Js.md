---
title: "[Coding Test - Greedy] Gym Clothes in Js"
labels: ["CodingTest","Gym Clothes","Archive"]
published: true
date: 2021-05-22T17:22:17+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 99
tistoryUrl: "https://yeolceo.tistory.com/99"
tistoryCategory: "CodingTest"
tistoryTags: ["체육복","코딩테스트"]
tistoryPostedAt: "2021-05-22 17:22:17"
language: en
bloggerPostId: "4886346461160370838"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/99/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/99/img_1.webp)

Let me explain the problem using the first example.

Out of n students, the ones without gym clothes are in lost, the rest have a set, and the ones with two sets are in reserve.

But if a student is listed in both reserve and lost, they count as having one set. And students with two sets can only lend to the student whose number is theirs +1 or -1.

So in the first for loop, I checked who's in both lost and reserve.

In the second for loop, I compared +1 and -1 and gave the spare gym clothes to the students without any.

I used -1 so it wouldn't interfere with the array's max value. Some people solved it more cleanly,

so it's worth checking the solutions on Programmers too.

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

Then I filtered out the -1s and took the remaining array values to get the number of students who have gym clothes.

Happy, diligent coding.
