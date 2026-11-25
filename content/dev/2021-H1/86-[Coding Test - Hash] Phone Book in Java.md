---
title: "[Coding Test - Hash] Phone Book in Java"
labels: ["CodingTest","hash","Phone Number","Archive"]
published: true
date: 2021-02-16T11:43:52+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 86
tistoryUrl: "https://yeolceo.tistory.com/86"
tistoryCategory: "CodingTest/hash"
tistoryTags: ["코딩테스트","코딩테스트","전화번호"]
tistoryPostedAt: "2021-02-16 11:43:52"
language: en
bloggerPostId: "73411247626058416"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/86/img.webp)

I ran this before writing it up, but if you spot a problem, please point it out anytime.

### **Phone Book**

Problem: If any number in the phone book is a prefix of another number, return false; if there's no such case, return true.

Constraints

-   phone\_book has a length between 1 and 1,000,000.
-   Each phone number is between 1 and 20 characters long.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/86/img_1.webp)

The category was hash, but I just wanted to get something working first, so here's what I came up with.

I used a nested for loop, and whenever substring went past the string's length, I just swallowed it all with a try lol... (how did this pass the efficiency tests..)

```html
class Solution {
    public boolean solution(String[] phone_book) {
        boolean answer = true;

          int len = phone_book.length;

        for(int i = 0; i< len ; i++){
            for(int j= 0; j<len; j++){
                try{
                    if(j!=i && phone_book[i].equals( phone_book[j].substring(0,phone_book[i].length())  ) ){
                            return false;
                    }
                }catch(Exception e){

                }
            }
        }

        return true;
    }
}
```

This problem was in the hash category, but a lot of people didn't use a hash. The approach is the same as mine,

but I brought this one in because it uses startsWith and the code is clean.

```html
class Solution {
    public boolean solution(String[] phoneBook) {

       for(int i=0; i<phoneBook.length-1; i++) {
            for(int j=i+1; j<phoneBook.length; j++) {
            //a nested for loop over i and j, using startsWith to compare only the prefix.
                if(phoneBook[i].startsWith(phoneBook[j])) {return false;}
                if(phoneBook[j].startsWith(phoneBook[i])) {return false;}
            }
        }
        return true;
    }
}
```

Not many people used a hash, and the code that did felt like the nested-loop code I showed earlier

with a hash and an iterator squeezed in, so I won't bother posting it.

Coding tests are worth practicing consistently. Happy, diligent coding!
