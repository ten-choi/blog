---
title: "[코딩 테스트 - 해시] 위장 in Java"
labels: ["CodingTest","hash","Java","위장","코딩테스트"]
published: true
date: 2021-03-05T16:16:49+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 89
tistoryUrl: "https://yeolceo.tistory.com/89"
tistoryCategory: "CodingTest/hash"
tistoryTags: ["Java","위장","코딩테스트"]
tistoryPostedAt: "2021-03-05 16:16:49"
language: ko
bloggerPostId: "5417914116857587014"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/89/img.webp)

실행해보고 글로 남기지만 문제가 있다면 언제든 지적 부탁드립니다.

### **위장**

문제 : 의상이 담긴 2차원 배열 clothes가 주어질 때 서로 다른 옷의 조합의 수를 return 하도록 solution 함수를 작성해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/89/img_1.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/89/img_2.webp)

제한사항

-   clothes의 각 행은 \[의상의 이름, 의상의 종류\]로 이루어져 있습니다.
-   스파이가 가진 의상의 수는 1개 이상 30개 이하입니다.
-   같은 이름을 가진 의상은 존재하지 않습니다.
-   clothes의 모든 원소는 문자열로 이루어져 있습니다.
-   모든 문자열의 길이는 1 이상 20 이하인 자연수이고 알파벳 소문자 또는 '\_' 로만 이루어져 있습니다.
-   스파이는 하루에 최소 한 개의 의상은 입습니다.

문제를 요약하자면

상의 2개 \[빨강 옷, 파랑 옷\], 모자 2개 \[노란 모자, 초록 모자\], 신발 3개 \[주황 신발, 갈색 신발, 흰색 신발\]

이렇게 옷이 있다면 외출할 때 1개 이상의 종류를 입어야 할 때 경우의 수를 나타내라는 문제입니다.

"포인트는 입지 않았다"의 개념입니다. 예를 들어 노란 모자를 쓰고 주황 신발을 신었지만 상의를 입지 않았다면?

그래서 없다의 경우의 수도 추가해야하기때문에 상의는 2개지만 경우의 수는 3개입니다. 

이 개념이 옷 종류별로 각각 적용됩니다. 단, 입지 않았다의 개념이 상의, 모자, 신발에 적용돼버리면

모든 옷을 입지 않은 케이스이기 때문에 이경우는 수로 인정되지 않습니다. 그래서 1을 빼줍니다.

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

다른 사람 풀이를 봤는데 시작부터 다르더군요. Java8 좀 하신 듯.. 

import를 static으로 가져와서 호출한 함수 선언 없이 사용해주는 걸로 시작합니다.

```html
import java.util.*;
import static java.util.stream.Collectors.*; //static 으로 사용해서 Collectors 내부 메소드를
											//Collectors선언 없이 사용합니다.

class Solution {
    public int solution(String[][] clothes) {
        return Arrays.stream(clothes)       // 해당 배열을 stream으로 치환합니다.
                .collect(groupingBy(p -> p[1], mapping(p -> p[0], counting()))) 

                .values()  //키와 값중에 값을 추려냅니다.
                .stream()  //collect 써주려고 다시 stream 화합니다.

                .collect(reducing(1L, (x, y) -> x * (y + 1))).intValue() - 1;
    }
}
```

코딩 테스트는 꾸준히 실천하시면 좋습니다. 성실한 코딩 하세요!
