---
title: "javascript 불변성 정확하게 설명해드립니다"
labels: ["TS","JS","javascript","불변성","자바스크립트"]
published: false
date: 2021-01-29T11:29:22+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 79
tistoryUrl: "https://yeolceo.tistory.com/79"
tistoryCategory: "TS, JS/javascript"
tistoryTags: ["불변성","javascript","js","자바스크립트","javascript"]
tistoryPostedAt: "2021-01-29 11:29:22"
language: ko
bloggerPostId: "8457750026439674626"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/79/img.webp)

### **\-javascript Type 설명**

**javascript**에서 데이터 타입은 2가지로 나뉩니다. **원시 타입**과 **참조 타입입니다.**

원시 타입은 **number**(숫자), **boolean**(논리), **string**(문자), **undefined**(초기화 안 함), **null**(없다고 초기화)가 있습니다.

![초기화 안해주면 undefined인거 설명하는 이미지](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/79/img_1.webp)

참조 타입은 **array**(배열), **function**(함수),  **object**(객체)가 있습니다. 

왜 **javascript** 는 데이터 타입을 크게 **2가지**로 나누었을까요? 차이는 **저장 방식**에서 나옵니다.

### **\-javascript 메모리 저장 방식**

javascript는 값을 저장할 때 변수와 값을 **나누어** 저장해줍니다.

이 말이 어떤 말이냐면 **x= 2** 라면 **변수** x를 저장하는 메모리 따로 **값** 2를 저장하는 메모리 따로 저장하는 개념이란 뜻입니다.

**원시 타입 예제**를 통해 설명드리겠습니다.

\-예시 코드-

```html
let x = 3;   //원시타입
let y = 5;
let z = x;

console.log(x); // 3   *100
console.log(y): // 5   *101
console.log(z): // 3   *100
```

<table style="border-collapse: collapse; width: 98.783%; height: 69px;" border="1" data-ke-style="style13"><tbody><tr style="height: 20px;"><td style="width: 16.1393%; height: 20px; text-align: center;">주소</td><td style="width: 27.1699%; height: 20px; text-align: center;">100</td><td style="width: 28.7975%; height: 20px; text-align: center;">101</td><td style="width: 27.8933%; height: 20px; text-align: center;">102</td></tr><tr style="height: 20px;"><td style="width: 16.1393%; height: 20px; text-align: center;"><span style="color: #333333;">메모리&nbsp;</span></td><td style="width: 27.1699%; height: 20px; text-align: center;"><span style="color: #333333;">x = *200</span></td><td style="width: 28.7975%; height: 20px; text-align: center;"><span style="color: #333333;">y = *201</span></td><td style="width: 27.8933%; height: 20px; text-align: center;"><span style="color: #333333;">z = *200</span></td></tr></tbody></table>

<table style="letter-spacing: 0px; border-collapse: collapse; width: 98.3776%; height: 40px;" border="1" data-ke-style="style15"><tbody><tr style="height: 20px;"><td style="width: 16.1651%; height: 20px; text-align: center;">주소</td><td style="width: 27.7295%; height: 20px; text-align: center;">200</td><td style="width: 29.1742%; height: 20px; text-align: center;">201</td><td style="width: 29.9002%; height: 20px; text-align: center;">202</td></tr><tr style="height: 20px;"><td style="width: 16.1651%; height: 20px; text-align: center;"><span>메모리</span></td><td style="width: 27.7295%; height: 20px; text-align: center;">3</td><td style="width: 29.1742%; height: 20px; text-align: center;">5</td><td style="width: 29.9002%; height: 20px; text-align: center;">&nbsp;</td></tr></tbody></table>

x =  데이터 3이 저장되어있는 **200 주소 사용**      y =  데이터 5가 저장되어있는 **201 주소 사용**

z =  데이터 3이 저장되어있는 **200 주소 사용**  

변수는 주소를 가진 채로 메모리에 변수명을 보존하고 있고  값은 값 자체를 메모리에 보존하고 있습니다. 

z = x 같은 식을 만들게 된다면 같은 **주소를 공유하여 메모리**를 사용합니다.

만약 이상태에서 값을 바꾸어 준다면 어떻게 될까요?

\-예시 코드-

```html
let x = 3;   //원시타입
let y = 5;
let z = x;

z = 7;   //이걸해주면 

console.log(x); // 3   *100
console.log(y): // 5   *101
console.log(z): // 7   *102
```

<table style="border-collapse: collapse; width: 99.5349%; height: 62px;" border="1" data-ke-style="style13"><tbody><tr style="height: 20px;"><td style="width: 16.1393%; height: 20px; text-align: center;">주소</td><td style="width: 27.1699%; height: 20px; text-align: center;">100</td><td style="width: 28.7975%; height: 20px; text-align: center;">101</td><td style="width: 27.8933%; height: 20px; text-align: center;">102</td></tr><tr style="height: 20px;"><td style="width: 16.1393%; height: 20px; text-align: center;"><span style="color: #333333;">메모리</span></td><td style="width: 27.1699%; height: 20px; text-align: center;">x = *200</td><td style="width: 28.7975%; height: 20px; text-align: center;"><span style="color: #333333;">y = *201</span></td><td style="width: 27.8933%; height: 20px; text-align: center;"><span style="color: #333333;">z = *202</span></td></tr></tbody></table>

<table style="letter-spacing: 0px; border-collapse: collapse; width: 99.3644%; height: 75px;" border="1" data-ke-style="style15"><tbody><tr style="height: 20px;"><td style="width: 16.5819%; text-align: center; height: 20px;">주소</td><td style="width: 27.0629%; text-align: center; height: 20px;">200</td><td style="width: 28.0304%; text-align: center; height: 20px;">201</td><td style="width: 28.2085%; text-align: center; height: 20px;">202</td></tr><tr style="height: 21px;"><td style="width: 16.5819%; text-align: center; height: 21px;"><span>메모리</span></td><td style="width: 27.0629%; text-align: center; height: 21px;">3</td><td style="width: 28.0304%; text-align: center; height: 21px;">5</td><td style="width: 28.2085%; text-align: center; height: 21px;">7</td></tr></tbody></table>

x =  데이터 3이 저장되어있는 **200 주소 사용**      y =  데이터 5가 저장되어있는 **201 주소 사용**

z =  데이터 7이 저장되어있는 **202 주소 사용**  

원시 타입의 경우 z의 값을 변경한다면 새로운 메모리 공간에 값을 넣어주고 그 주소를 사용합니다. 

하지만 **참조 타입**의 경우 방식이 달라집니다.

\-예시 코드-

```html
let obj ={
     a:10,
     b:21
}

let copy = obj;
console.log(obj);
copy.b= 0;
console.log(obj);
```

<table style="letter-spacing: 0px; border-collapse: collapse; width: 100%; height: 40px;" border="1" data-ke-style="style13"><tbody><tr style="height: 20px;"><td style="width: 14.3951%; height: 20px; text-align: center;">주소</td><td style="width: 28.7978%; height: 20px; text-align: center;">100</td><td style="width: 28.9138%; height: 20px; text-align: center;">101</td><td style="width: 27.8933%; height: 20px; text-align: center;">102</td></tr><tr style="height: 20px;"><td style="width: 14.3951%; height: 20px; text-align: center;"><span>메모리</span></td><td style="width: 28.7978%; height: 20px; text-align: center;">obj = *200~*201</td><td style="width: 28.9138%; height: 20px; text-align: center;"><span>copy = *200~*201</span></td><td style="width: 27.8933%; height: 20px; text-align: center;">&nbsp;</td></tr></tbody></table>

<table style="letter-spacing: 0px; border-collapse: collapse; width: 100%; height: 40px;" border="1" data-ke-style="style15"><tbody><tr style="height: 20px;"><td style="width: 14.3951%; height: 20px; text-align: center;">주소</td><td style="width: 28.6815%; height: 20px; text-align: center;">200</td><td style="width: 29.2627%; height: 20px; text-align: center;">201</td><td style="width: 27.6607%; height: 20px; text-align: center;">202</td></tr><tr style="height: 20px;"><td style="width: 14.3951%; height: 20px; text-align: center;"><span>메모리</span></td><td style="width: 28.6815%; height: 20px; text-align: center;">a = *300</td><td style="width: 29.2627%; height: 20px; text-align: center;">b = *301</td><td style="width: 27.6607%; height: 20px; text-align: center;">&nbsp;</td></tr></tbody></table>

<table style="letter-spacing: 0px; border-collapse: collapse; width: 100%; height: 39px;" border="1" data-ke-style="style12"><tbody><tr style="height: 19px;"><td style="width: 14.5349%; height: 19px; text-align: center;">주소</td><td style="width: 28.9535%; height: 19px; text-align: center;">300</td><td style="width: 28.721%; height: 19px; text-align: center;">301</td><td style="width: 27.6744%; height: 19px; text-align: center;">302</td></tr><tr style="height: 20px;"><td style="width: 14.5349%; height: 20px; text-align: center;"><span>메모리</span></td><td style="width: 28.9535%; height: 20px; text-align: center;">10</td><td style="width: 28.721%; height: 20px; text-align: center;">21</td><td style="width: 27.6744%; height: 20px; text-align: center;">&nbsp;</td></tr></tbody></table>

눈치채셨나요?

원시 타입의 경우 값을 변경한다면 새로운 메모리 공간에 값을 만들어주었는데 참조 타입의 경우는

copy의 값을 변경했더니 원래 object의 값도 변경이 돼버렸습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/79/img_2.webp)

왜인지 이해하기 쉽게 설명드리겠습니다. 코딩하면서 아래의 표와 함께 진행해주시면 이해하시기 좋습니다.

<table style="border-collapse: collapse; width: 100%; height: 40px;" border="1" data-ke-style="style13"><tbody><tr style="height: 20px;"><td style="height: 20px; width: 10.9302%; text-align: center;">주소</td><td style="height: 20px; width: 25.4651%; text-align: center;">100</td><td style="height: 20px; width: 33.3721%; text-align: center;">101</td><td style="height: 20px; width: 30.1163%; text-align: center;">102</td></tr><tr style="height: 20px;"><td style="height: 20px; width: 10.9302%; text-align: center;"><span style="color: #333333;">메모리</span></td><td style="height: 20px; width: 25.4651%; text-align: center;">obj = *200~*201</td><td style="height: 20px; width: 33.3721%; text-align: center;"><span style="color: #333333;">copy = *200~*201</span></td><td style="height: 20px; width: 30.1163%; text-align: center;">&nbsp;</td></tr></tbody></table>

<table style="border-collapse: collapse; width: 100%; height: 40px;" border="1" data-ke-style="style15"><tbody><tr style="height: 20px;"><td style="height: 20px; width: 10.4651%; text-align: center;">주소</td><td style="height: 20px; width: 26.3953%; text-align: center;">200</td><td style="height: 20px; width: 33.0233%; text-align: center;">201</td><td style="height: 20px; width: 30%; text-align: center;">202</td></tr><tr style="height: 20px;"><td style="height: 20px; width: 10.4651%; text-align: center;"><span style="color: #333333;">메모리</span></td><td style="height: 20px; width: 26.3953%; text-align: center;">a = *300</td><td style="height: 20px; width: 33.0233%; text-align: center;">b = *301</td><td style="height: 20px; width: 30%; text-align: center;">&nbsp;</td></tr></tbody></table>

<table style="border-collapse: collapse; width: 100%; height: 40px;" border="1" data-ke-style="style12"><tbody><tr style="height: 20px;"><td style="width: 10.4651%; height: 20px; text-align: center;">주소</td><td style="width: 26.6279%; height: 20px; text-align: center;">300</td><td style="width: 32.5581%; height: 20px; text-align: center;">301</td><td style="width: 30.2326%; height: 20px; text-align: center;">302</td></tr><tr style="height: 20px;"><td style="width: 10.4651%; height: 20px; text-align: center;"><span style="color: #333333;">메모리</span></td><td style="width: 26.6279%; height: 20px; text-align: center;">10</td><td style="width: 32.5581%; height: 20px; text-align: center;">21 -&gt; 0</td><td style="width: 30.2326%; height: 20px; text-align: center;">&nbsp;</td></tr></tbody></table>

저희는 **copy.b**의 값을 0으로 변경했습니다. 즉 **201**의 값을 변경했기 때문에 **301** 이 0 이 됩니다.

하지만 **100**과 **101** 은 아무것도 모른 채 **주소를 유지**하고 있는 것입니다. 저희는 copy.b만 변경했고 그 주소에 해당하는 값만 변경했거든요.

그래서 301 은 0이 되고 원본도 결국 **object.b** 가 **0**으로 표현되는 것입니다.

### **\-결론-**

**원본을 보존하기** 위해 카피본을 사용하는 경우가 많고 그렇기 때문에 이 부분은 **큰 문제**가 되겠죠?

그래서 이러한 **불상사**를 막기 위해 **불변성 유지** \= (카피본을 바꿔도 원본은 변경되면 안 됩니다) 

를 하라는 말이 나온 것입니다.

**javascript 불변성**에 대해 간단히 이해하셨길 바랍니다. 성실한 코딩 하세요.
