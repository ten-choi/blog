---
title: "[코딩 테스트 - 해시] 전화번호 목록 in Java"
labels: ["CodingTest","hash","코딩테스트","전화번호"]
published: false
date: 2021-02-16T11:43:52+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 86
tistoryUrl: "https://yeolceo.tistory.com/86"
tistoryCategory: "CodingTest/hash"
tistoryTags: ["코딩테스트","코딩테스트","전화번호"]
tistoryPostedAt: "2021-02-16 11:43:52"
language: ko
bloggerPostId: "73411247626058416"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/86/img.webp)

실행해보고 글로 남기지만 문제가 있다면 언제든 지적 부탁드립니다.

### **전화번호 목록**

문제 : 전화번호부 안에 한 번호가 만약 다른 번호의 접두어가 될 경우 false를 반환하고 그런 경우가 없다면 true를 반환하시오

조건

-   phone\_book의 길이는 1 이상 1,000,000 이하입니다.
-   각 전화번호의 길이는 1 이상 20 이하입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/86/img_1.webp)

카테고리는 해시였지만 그냥 완성부터 해버리고 싶어서 일단 완성한 코드입니다. 

이중 for문을 사용했고 substring으로 잘라낼 때 길이 초과해서 잘라내는 거 try로 다 뭉게 버렸습니다 ㅋㅋ... (효율성 어떻게 통과했니..)

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

hash 카테고리에 있던 문제였는데 많은 분들이 hash를 쓰지 않으시더라고요. 방식은 저와 동일하지만

startWith 문법 사용 및 깔끔한 코드여서 가지고 왔습니다.

```html
class Solution {
    public boolean solution(String[] phoneBook) {

       for(int i=0; i<phoneBook.length-1; i++) {
            for(int j=i+1; j<phoneBook.length; j++) {
            //i 와 j를 통한 이중for 문인데 startWith라는 함수를 사용해 접두어만 비교합니다.
                if(phoneBook[i].startsWith(phoneBook[j])) {return false;}
                if(phoneBook[j].startsWith(phoneBook[i])) {return false;}
            }
        }
        return true;
    }
}
```

해시를 많이 사용하시지 않거나 사용된 코드도 기존에 보여드린 이중 포문 코드에서

해시와 이터레이터만 끼워 넣은 느낌이라 굳이 올리진 않겠습니다.

코딩 테스트는 꾸준히 실천하시면 좋습니다. 성실한 코딩 하세요!
