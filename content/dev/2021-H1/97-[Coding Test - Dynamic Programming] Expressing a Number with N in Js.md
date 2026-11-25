---
title: "[Coding Test - Dynamic Programming] Expressing a Number with N in Js"
labels: ["CodingTest","Archive"]
published: true
date: 2021-05-22T17:07:37+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 97
tistoryUrl: "https://yeolceo.tistory.com/97"
tistoryCategory: "CodingTest"
tistoryTags: ["코딩테스트","N으로"]
tistoryPostedAt: "2021-05-22 17:07:37"
language: en
bloggerPostId: "8719183697193588770"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/97/img.webp)

This one's "Expressing a Number with N."

I create 8 arrays as Sets to remove duplicates.

The problem lets you use N up to 8 times. So when declaring them, you need to put the N value in up front.

That's because, apart from arithmetic, the other way to use N is concatenation: if N is 5, then 55, 555, 5555 and so on use the number 5

without any operation, so I put those in up front.

After that, I compute the values with nested loops.

Using N once

When i and j are 0, 0, the inner for loop doesn't run, so we just check arr\[i\]. -> At the start I put a single 5 into arr\[0\].

I check with the Set's has method.

Using N twice

The inner for loop starts running once i goes up. arr\[0\] and arr\[0\] go through the four arithmetic operations and fill arr\[1\].

So arr\[1\] gets the results of the four operations using N twice plus the 55 we put in earlier: 55, 5+5, 5-5, 5\*5, 5/5.

Then we again check whether number is in arr\[1\].

Using N three times

Same thing, but now for arr\[2\], which already holds 555, we combine arr\[0\] (N used once) with arr\[1\] (N used twice).

arr\[2\] gets numbers like 555, 55+5, 55-5, 55\*5, 55/5... 5/55. Duplicates get removed along the way,

and I just left negatives and fractions alone, since number is always an integer anyway.

I keep going like this for N4, N5, and if it goes past 8 uses, I return -1.

```html
function solution(N, number) {

    const arr = new Array(8).fill().map((v,i) => new Set(
        [parseInt(N.toString().repeat(i+1))]
    ));
    // const arr = new Array(8).fill(new Set());  filling it directly causes a timeout error
    //const arr = new Array(8).fill().map(()=>new Set()); no error with map, why?
    for(let i=0; i<8; i++){
        // arr[i].add(parseInt(N.toString().repeat(i+1)));
        for(let j=0; j<i; j++){
            for(let item1 of arr[j]){
                for(let item2 of arr[i-j-1]){
                arr[i].add(item1+item2); 
                arr[i].add(item1-item2);
                arr[i].add(item1*item2);
                arr[i].add(item1/item2);
                }                
            }
        }
        if(arr[i].has(number)){
            return i+1;
        }
    }
    return -1;
}
```

If you use the commented-out line and put new Set() straight into fill, you get an error.. I'd be grateful if anyone could share why.

Happy, diligent coding.
