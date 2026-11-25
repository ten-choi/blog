---
title: "[Coding Test] String Compression in JS"
labels: ["CodingTest","String","Archive"]
published: true
date: 2021-06-02T17:54:18+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 101
tistoryUrl: "https://yeolceo.tistory.com/101"
tistoryCategory: "CodingTest"
tistoryTags: ["코딩테스트","문자열"]
tistoryPostedAt: "2021-06-02 17:54:18"
language: en
bloggerPostId: "2862640407958355640"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/101/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/101/img_1.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/101/img_2.webp)

This is the string compression problem.

Take 'aabccc': compressing in units of 1 gives '2ab3c'. Once a run reaches 3 or more characters, turning it into a number plus a string

actually shortens the length. Compressing in units of 2, 'ababcccc' becomes '2ab2cc'.

Keep going like this with units of 3, 4, 5... up to string.length, compress the string each time, and return the minimum length.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/101/img_3.webp)

Be careful: it doesn't work the way shown above.

Now for the solution. Take a look at the code.

```html
function solution(s) { 
    let resArr = new Set();  // holds the compressed string length for each unit size

    for (var i=1; i<=s.length; i++) {  // i=1 because we start by comparing substrings of length 1

        let count = 1;              // counts repeated substrings
        let addStr = '';            // the compressed string

        for (var j=0; j<s.length; j=j+i) { // loop from 0, stepping by i

            var curSub = s.slice(j, j+i);      // chunk starting at j
            var nextSub = s.slice(j+i, j+i+i); // the next chunk, starting at j+i

            if( curSub == nextSub) { // compare the current chunk with the next one
                count += 1;    // same means a repeat, so increment count
            } else { // if they differ
                if(count != 1){  // count isn't 1, so there was a repeat:
                				// append count + chunk to the result
                     addStr = addStr + count + curSub;
                } else { // count is 1, so no repeat: just append the chunk
                     addStr = addStr + curSub;
                }
                count = 1; // reset count before the next chunk
            }
        }
        resArr.add(addStr.length); // add the compressed length for unit size i
    }
    return Math.min(...resArr); // return the minimum
}
```

The problem boils down to compressing with each unit size i and returning the minimum. Happy coding.
