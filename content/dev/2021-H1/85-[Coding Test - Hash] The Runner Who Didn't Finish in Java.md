---
title: "[Coding Test - Hash] The Runner Who Didn't Finish in Java"
labels: ["CodingTest","hash","Marathon","Programmers","Archive"]
published: true
date: 2021-02-15T16:52:43+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 85
tistoryUrl: "https://yeolceo.tistory.com/85"
tistoryCategory: "CodingTest/hash"
tistoryTags: ["코딩테스트","완주하지","마라톤","프로그래머스","완주하지"]
tistoryPostedAt: "2021-02-15 16:52:43"
language: en
bloggerPostId: "5867935522739077877"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/85/codingtest.webp)

I ran this before writing it up, but if you spot a problem, please point it out anytime.

### **The Runner Who Didn't Finish**

Problem: Exactly one runner dropped out of a marathon. Write code that finds that person!

You're given two arrays: the participants array (participant) and the finishers array (completion).

Constraints

-   completion is one element shorter than participant.
-   Each participant's name is 1 to 20 lowercase letters.
-   There may be participants with the same name.

Here's how I coded it.

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

But the problem says to use a hash. So I looked up HashMap,

checked out some solutions, and wrote the code below.

```html
import java.util.HashMap;

class Solution {
    public String solution(String[] participant, String[] completion) {
        String answer="";
        HashMap<String, Integer> hm = new HashMap<>(); //declared as key-value pairs

        // add participants to the hash; for duplicate names, value +1
        for(String player: participant ){ //for-each loop
            hm.put(player, hm.getOrDefault(player, 0) +1 );  // getOrDefault returns a default value if the key is missing
        }
        // for finishers, value -1 in the hash
        for(String player: completion ){
            hm.put(player, hm.get(player) -1);
        }
        // keySet returns the keys of this hash map as a collection
        for(String key : hm.keySet() ){
           if(hm.get(key)!=0)answer=key; // if it's not 0, one is left over, so that's the one who dropped out
        }
        return answer;
    }
}
```

There's also code like this. The two for loops at the top of the main code have the same structure as the code we just saw.

The bottom part brings in List and Iterator and uses keys.hasNext in a while loop. I thought that alone showed plenty of knowledge of List and Iterator,

but then it uses another for loop inside and calls list.add, and I wondered whether that extra for loop inside the while was really needed, so I brought it here.

```html
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

class Solution {
    public String solution(String[] participant, String[] completion) {

        Map<String, Integer> map = new HashMap<>();
        // add participants
        for (String p:participant)  {
            if(map.get(p) != null){
                map.put(p, map.get(p) + 1);
            }else{
                map.put(p,1);
            }
        }
        // add finishers
        for (String c:completion){
            if(map.get(c) != 0) {
                map.put(c, map.get(c) - 1);
            }
        }
        // from here on is the part I find puzzling
        List<String> list = new ArrayList<>();
        Iterator<String> keys = map.keySet().iterator(); //uses this method to get the collection of keys
                                      //through the standard Iterator interface.
        while( keys.hasNext() ){  // loops over the iterator's elements; returns a boolean -> false when there are none left
            String key = keys.next();  // next() returns the element
            if(map.get(key) != 0) {       // the moment you find a key whose value in map isn't 0, you already have the answer
                for(int i = 0; i < map.get(key); i++) { //adds a for loop
                    list.add(key);                      //uses a list
                }
            } 
        }
        String answer = list.get(0);   //reads it back with list.get(0)
        return answer;
    }
}
```

There's also some slick code out there that leans on Java 8 or builds its own hash structure, but since this is a level 1 problem, I'll wrap it up here.

Added a JavaScript version (edited January 6, 2022)

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

Below is what I hacked together at first

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

   This blows up (O(n^2)): two loops go through every combination, so it fails the efficiency tests lol
```

If you're a junior developer, coding tests are a must! Happy, diligent coding.
