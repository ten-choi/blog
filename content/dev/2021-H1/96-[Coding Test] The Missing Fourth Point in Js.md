---
title: "[Coding Test] The Missing Fourth Point in Js"
labels: ["CodingTest","Archive"]
published: true
date: 2021-05-22T16:53:06+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 96
tistoryUrl: "https://yeolceo.tistory.com/96"
tistoryCategory: "CodingTest"
tistoryTags: ["코딩테스트","나머지"]
tistoryPostedAt: "2021-05-22 16:53:06"
language: en
bloggerPostId: "8033083875057385672"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/96/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/96/img_1.webp)

I found the pattern.

In the first coordinate, one number shows up twice and another shows up once. Same idea for the second coordinate.

Using the first example, index \[0\] of the arrays is 1, 3, 3, so 3 is the duplicate.

Index \[1\] is 4, 4, 10, so 4 is the duplicate. Cancel out the duplicates and you're left with one coordinate.

\[1, 10\] is the result. That's how I found the answer.

```html
function solution(v) {
    let arr1=new Set(), arr2=new Set();   // a Set is basically like an array; I used it to get comfortable with ES6. (Give it a try too)
    for(let i of v){
        arr1.has(i[0])?arr1.delete(i[0]):arr1.add(i[0]);   // if the same number is already there, remove it. index 0
        arr2.has(i[1])?arr2.delete(i[1]):arr2.add(i[1]);   // if the same number is already there, remove it. index 1
    }
    return [...arr1, ...arr2]; // use the spread operator to put each number into an array.
}
```

Someone else used the same idea as me but wrote it with ^= (XOR). In my book, the bitwise version was the most efficient code.

Mine is basically that bitwise idea spelled out. Thanks for reading, and happy, diligent coding.
