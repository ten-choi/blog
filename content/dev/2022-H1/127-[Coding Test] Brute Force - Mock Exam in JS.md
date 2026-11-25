---
title: "[Coding Test] Brute Force - Mock Exam in JS"
labels: ["CodingTest","Mock Exam","Programmers","Archive"]
published: true
date: 2022-02-22T00:22:31+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 127
tistoryUrl: "https://yeolceo.tistory.com/127"
tistoryCategory: "CodingTest"
tistoryTags: ["모의고사","코딩테스트","프로그래머스"]
tistoryPostedAt: "2022-02-22 00:22:31"
language: en
bloggerPostId: "4403770253917935501"
---
#### Environment

JavaScript

#### Overview

Solving a coding test problem on Programmers

#### [**See it on git**](https://github.com/ChoiYeol/Algorithm_Programmers/blob/main/LV1_%EB%AA%A8%EC%9D%98%EA%B3%A0%EC%82%AC.js)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/127/img.webp)

```html
function solution(answers) {
    let p1=0
    let p2=0
    let p3=0
    let filt;
    let res=[];
    let arr1=[1, 2, 3, 4, 5]
    let arr2=[2, 1, 2, 3, 2, 4, 2, 5]
    let arr3=[3, 3, 1, 1, 2, 2, 4, 4, 5, 5]

    answers.map((v, i)=>{
      if( arr1[i%arr1.length] === v )p1++
      if( arr2[i%arr2.length] === v )p2++
      if( arr3[i%arr3.length] === v )p3++
    })
    filt = [p1, p2, p3]
    filt.filter((el, i)=>{
        if(el== Math.max(...filt)){
            res.push(i+1)
        }
    })
    return res;
}
```

I think the key point is whether you use %. Most other solutions looked pretty similar.

Happy coding, and keep at it.
