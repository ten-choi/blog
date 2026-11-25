---
title: "[Coding Test] Phoneketmon in Js"
labels: ["CodingTest","Phoneketmon","Archive"]
published: true
date: 2021-05-22T17:13:53+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 98
tistoryUrl: "https://yeolceo.tistory.com/98"
tistoryCategory: "CodingTest"
tistoryTags: ["코딩테스트","폰켓몬"]
tistoryPostedAt: "2021-05-22 17:13:53"
language: en
bloggerPostId: "6912782248161498416"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/98/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/98/img_1.webp)

It could've been more concise, but I wanted a one-liner, so I forced it into one line.

The problem is simple.

When N is nums.length, i.e. the number of Pokémon,

you can take N/2 of them, but only one per species. So if species #3 shows up four times, as 3, 3, 3, 3, you can only

take one of them.

In other words: remove duplicates, and if the deduplicated count is smaller than N/2, return that count; otherwise return N/2.

```html
function solution(nums) {

    return nums.length/2 < new Set(nums).length? 
    nums.length/2 : Array.from(new Set(nums)).length;
}
```

Happy, diligent coding.
