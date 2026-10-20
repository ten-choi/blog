---
title: "[코딩 테스트 - 해시] 완주하지 못한 선수 in Java"
labels: ["CodingTest","hash","코딩테스트","완주하지","마라톤","프로그래머스"]
published: false
date: 2021-02-15T16:52:43+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 85
tistoryUrl: "https://yeolceo.tistory.com/85"
tistoryCategory: "CodingTest/hash"
tistoryTags: ["코딩테스트","완주하지","마라톤","프로그래머스","완주하지"]
tistoryPostedAt: "2021-02-15 16:52:43"
language: ko
bloggerPostId: "5867935522739077877"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/85/codingtest.webp)

실행해보고 글로 남기지만 문제가 있다면 언제든 지적 부탁드립니다.

### **완주하지 못한 선수**

문제 : 마라톤 대회에서 한 명만 리타이어 했는데 그 사람을 찾는 코드를 만들어라!입니다.

출전자 배열(completion)과 완주자 배열(participant) 이렇게 2개의 배열이 주어집니다.

조건

-   completion의 길이는 participant의 길이보다 1 작습니다.
-   참가자의 이름은 1개 이상 20개 이하의 알파벳 소문자로 이루어져 있습니다.
-   참가자 중에는 동명이인이 있을 수 있습니다.

제 경우에는 아래와 같은 방식으로 코딩했습니다.

```html
import java.util.*;
class Solution {
    public String solution(String[] participant, String[] completion) {
        Arrays.sort(participant);
        Arrays.sort(completion);
        int len = completion.length;
        int i;

        for ( i=0; i<len; i++){
            if (!participant[i].equals(completion[i])){
                return participant[i];
            }
        }
        return participant[len];
    }
}
```

하지만 문제에서 hash를 사용하라는 지시사항이 있습니다. 그래서 

HashMap을 찾아보고 풀이도 찾아보며 아래와 같은 방식의 코드를 만들었습니다.

```html
import java.util.HashMap;

class Solution {
    public String solution(String[] participant, String[] completion) {
        String answer="";
        HashMap<String, Integer> hm = new HashMap<>(); //key value 형식의 선언

        // 출전자들을 해시에 추가하며 동명이인의 경우 value 값 +1
        for(String player: participant ){ //for each 문
            hm.put(player, hm.getOrDefault(player, 0) +1 );  // getOrDefault 없으면 디폴트값 주는 함수
        }
        // 완주자들을 해시에서 value -1
        for(String player: completion ){
            hm.put(player, hm.get(player) -1);
        }
        // keySet 함수를 통해 해당 해시맵 변수의 키값들을 배열로 호출
        for(String key : hm.keySet() ){
           if(hm.get(key)!=0)answer=key; // 0이 아니면 한명 남았으니까 리타이어 한 사람
        }
        return answer;
    }
}
```

이런 코드도 있습니다. main 코드 위쪽의 for문 2개는 이전에 보았던 코드와 동일한 구조입니다.

아랫부분은 List와 Iterator를 넣고 while에 keys.hasNext를 사용합니다. 이 정도면 충분히  List와 Iterator에 대한 지식을 보여줬다고 생각했는데 

안에 for문을 한번 더 쓰고 list.add를 하길래 while 안에 저런 for문을 또 넣을 필요가 있나 의아해서 가져온 코드입니다.

```html
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

class Solution {
    public String solution(String[] participant, String[] completion) {

        Map<String, Integer> map = new HashMap<>();
        // 출전자 추가
        for (String p:participant)  {
            if(map.get(p) != null){
                map.put(p, map.get(p) + 1);
            }else{
                map.put(p,1);
            }
        }
        // 완주자 추가
        for (String c:completion){
            if(map.get(c) != 0) {
                map.put(c, map.get(c) - 1);
            }
        }
        // 여기서부터 필자가 의아하게 보는 부분
        List<String> list = new ArrayList<>();
        Iterator<String> keys = map.keySet().iterator(); //키값을 모아놓은 배열을
                                      //표준화된 이터레이터 인터페이스로 불러주기위해 해당 메소드 사용합니다.
        while( keys.hasNext() ){  // 이터레이터의 요소 만큼 반복하는데 bool 값을 반환 -> 없으면 false
            String key = keys.next();  // 해당 요소 반환해주는 next() 메소드
            if(map.get(key) != 0) {       // 해당 키값으로 map에서 value가 0이 아닌놈을 찾는 순간 이미 결과나옴
                for(int i = 0; i < map.get(key); i++) { //for문 추가
                    list.add(key);                      //list 사용
                }
            } 
        }
        String answer = list.get(0);   //list.get(0) 으로 호출
        return answer;
    }
}
```

Java 8을 많이 사용했거나 해쉬 구조를 만들거나 하는 멋진 코드도 있지만 레벨 1 문제이니만큼 이쯤에서 마무리합니다.

javascript로 짠거 추가 22년 1월 6일 수정

```html
function solution(participant, completion) {
    participant.sort()
    completion.sort()
    return participant.find((part, i)=>{
        if(i == completion.length) return part;
        return part !=completion[i];
    }) 

}
```

아래가 처음에 막짠거

```html
return participant.find((part)=>{ 
        let res =0; 
        completion.map((com, j)=>{
            if(part == com && res ==0 ){
                completion[j]='';
                res=1; 
            }
        })
        return res ==0;
    })

   n펙토리얼이 됨 for문 2개로 경우에 수 다 돌리니까 효율성에서 떨굼 ㅋㅋㅋㅋㅋ
```

주니어개발자라면 코딩 테스트는 필수! 성실한 코딩 하세요.
