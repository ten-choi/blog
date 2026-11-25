---
title: "[Coding Test - Hash] Camouflage in Java"
labels: ["CodingTest","hash","Java","Camouflage","Archive"]
published: true
date: 2021-03-05T16:16:49+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 89
tistoryUrl: "https://yeolceo.tistory.com/89"
tistoryCategory: "CodingTest/hash"
tistoryTags: ["Java","위장","코딩테스트"]
tistoryPostedAt: "2021-03-05 16:16:49"
language: en
bloggerPostId: "5417914116857587014"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/89/img.webp)

I ran this before writing it up, but if you spot a problem, please point it out anytime.

### **Camouflage**

Problem: Given a 2D array clothes containing a spy's clothing items, write a solution function that returns the number of different combinations of clothes.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/89/img_1.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/89/img_2.webp)

Constraints

-   Each row of clothes is \[item name, item type\].
-   The spy has between 1 and 30 clothing items.
-   No two items have the same name.
-   Every element of clothes is a string.
-   Every string is 1 to 20 characters long and consists only of lowercase letters or '\_'.
-   The spy wears at least one item per day.

To sum up the problem:

If you have 2 tops \[red shirt, blue shirt\], 2 hats \[yellow hat, green hat\], and 3 pairs of shoes \[orange shoes, brown shoes, white shoes\],

count the number of ways to go out when you have to wear at least one type of item.

The key is the idea of "not wearing it." For example, what if you wear the yellow hat and the orange shoes but no top?

Since "none" also has to count as an option, there are 2 tops but 3 choices.

This applies to each clothing type separately. However, if "not wearing it" applies to tops, hats, and shoes all at once,

that's the case where you wear nothing at all, which doesn't count. So we subtract 1.

```html
import java.util.HashMap;
import java.util.Iterator;

class Solution {
    public int solution(String[][] clothes) {

        HashMap<String, Integer> hm = new HashMap<String, Integer>();
        Iterator<Integer> it;

        int answer = 1;
        for (int i = 0; i < clothes.length; i++) {
            hm.put(clothes[i][1], hm.getOrDefault(clothes[i][1], 0)+1);
        }
        it = hm.values().iterator();
        while(it.hasNext()){
            answer*= it.next() +1;
        }
        return answer-1;
    }
}
```

I looked at other people's solutions, and one was different from the very first line. Looks like they know their Java 8..

It starts with a static import so the methods can be called without naming the class.

```html
import java.util.*;
import static java.util.stream.Collectors.*; //static import lets you use the methods inside Collectors
											//without writing Collectors.

class Solution {
    public int solution(String[][] clothes) {
        return Arrays.stream(clothes)       // turns the array into a stream.
                .collect(groupingBy(p -> p[1], mapping(p -> p[0], counting()))) 

                .values()  //picks out the values (not the keys).
                .stream()  //turns it into a stream again so we can use collect.

                .collect(reducing(1L, (x, y) -> x * (y + 1))).intValue() - 1;
    }
}
```

Coding tests are worth practicing consistently. Happy, diligent coding!
