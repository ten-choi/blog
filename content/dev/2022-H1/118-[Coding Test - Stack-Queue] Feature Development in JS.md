---
title: "[Coding Test - Stack/Queue] Feature Development in JS"
labels: ["CodingTest","Programmers","Archive"]
published: true
date: 2022-01-10T15:15:01+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 118
tistoryUrl: "https://yeolceo.tistory.com/118"
tistoryCategory: "CodingTest"
tistoryTags: ["프로그래머스","코딩테스트","코딩테스트","코테"]
tistoryPostedAt: "2022-01-10 15:15:01"
language: en
bloggerPostId: "2107476554652624676"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/118/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/118/img_1.webp)

Here's my solution and explanation. On each pass of the loop I add each speed to its progress, and whenever deployable indexes (100 or more) show up, I count them and push that count into result.

Any index that's been deployed gets pushed into an array called checked, so it's excluded from the condition on the next iteration. Once the loop has gone all the way through, it exits with a break.

```html
function solution(progresses, speeds) {

    let res=[]; // answer
    let checked = [];  // indexes already added to res
    while(1){ // infinite loop
    	// add each speed to its current progress
        for(let i=0; i< progresses.length; i++){
            progresses[i] = progresses[i]+ speeds[i]
        }

        let num =0; // number of features to deploy
        for(let j=0; j< progresses.length; j++){
            if(!checked.includes(j)){  // skip ones already deployed
                if(progresses[j]>=100){  // check for 100 or more
                checked.push(j);  // record this index
                num+=1;  		// +1 to the deploy count
                    if(j== progresses.length-1){  // the last one never reaches the else, so push num here
                        res.push(num);
                        break;
                    }
                }else{ // push the deploy count into the answer and leave the for loop
                    if(num)res.push(num); 
                    break;
                }
            }
        }
        if(checked.length == progresses.length)break; // stop once every index has been handled
    }
    return res; // return
}
```

Once the logic was done, adding the part below that pushes the last value finished it off.

```html
if(j== progresses.length-1){
    res.push(num);
    break;
}
```

It was a simple problem, so I looked around for solutions different from mine, or ones closer to the problem's category, stack/queue. There were solutions similar to mine, just a bit more concise. The alternative below stood out, so I brought it here.  

It's a maxDay approach using **\[ (100 - progress) / speeds \]**. I was impressed that someone came up with this.

It reads well and the code itself feels clean, so I'm sharing it.

```html
function solution(progresses, speeds) {
    let answer = [0];
    let days = progresses.map((progress, index) => Math.ceil((100 - progress) / speeds[index]));
    let maxDay = days[0];

    for(let i = 0, j = 0; i< days.length; i++){
        if(days[i] <= maxDay) {
            answer[j] += 1;
        } else {
            maxDay = days[i];
            answer[++j] = 1;
        }
    }

    return answer;
}
```

Happy coding.
