---
title: "JavaScript Immutability, Explained Properly"
labels: ["TS","JS","javascript","Immutability","JavaScript","Archive"]
published: true
date: 2021-01-29T11:29:22+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 79
tistoryUrl: "https://yeolceo.tistory.com/79"
tistoryCategory: "TS, JS/javascript"
tistoryTags: ["불변성","javascript","js","자바스크립트","javascript"]
tistoryPostedAt: "2021-01-29 11:29:22"
language: en
bloggerPostId: "8457750026439674626"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/79/img.webp)

### **\-JavaScript Types**

In **JavaScript**, data types fall into two groups: **primitive types** and **reference types.**

The primitive types are **number**, **boolean**, **string**, **undefined** (not initialized), and **null** (explicitly initialized to "nothing").

![Image showing that a variable is undefined if you don't initialize it](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/79/img_1.webp)

The reference types are **array**, **function**, and **object**.

So why does **JavaScript** split data types into **two** big groups? The difference comes from **how they're stored**.

### **\-How JavaScript Stores Values in Memory**

When JavaScript stores a value, it stores the variable and the value **separately**.

What that means: for **x = 2**, the **variable** x lives in one memory slot and the **value** 2 lives in another.

Let me walk through it with a **primitive type example**.

\-Example code-

```html
let x = 3;   //primitive type
let y = 5;
let z = x;

console.log(x); // 3   *100
console.log(y); // 5   *101
console.log(z); // 3   *100
```

<table style="border-collapse: collapse; width: 98.783%; height: 69px;" border="1" data-ke-style="style13"><tbody><tr style="height: 20px;"><td style="width: 16.1393%; height: 20px; text-align: center;">Address</td><td style="width: 27.1699%; height: 20px; text-align: center;">100</td><td style="width: 28.7975%; height: 20px; text-align: center;">101</td><td style="width: 27.8933%; height: 20px; text-align: center;">102</td></tr><tr style="height: 20px;"><td style="width: 16.1393%; height: 20px; text-align: center;"><span style="color: #333333;">Memory&nbsp;</span></td><td style="width: 27.1699%; height: 20px; text-align: center;"><span style="color: #333333;">x = *200</span></td><td style="width: 28.7975%; height: 20px; text-align: center;"><span style="color: #333333;">y = *201</span></td><td style="width: 27.8933%; height: 20px; text-align: center;"><span style="color: #333333;">z = *200</span></td></tr></tbody></table>

<table style="letter-spacing: 0px; border-collapse: collapse; width: 98.3776%; height: 40px;" border="1" data-ke-style="style15"><tbody><tr style="height: 20px;"><td style="width: 16.1651%; height: 20px; text-align: center;">Address</td><td style="width: 27.7295%; height: 20px; text-align: center;">200</td><td style="width: 29.1742%; height: 20px; text-align: center;">201</td><td style="width: 29.9002%; height: 20px; text-align: center;">202</td></tr><tr style="height: 20px;"><td style="width: 16.1651%; height: 20px; text-align: center;"><span>Memory</span></td><td style="width: 27.7295%; height: 20px; text-align: center;">3</td><td style="width: 29.1742%; height: 20px; text-align: center;">5</td><td style="width: 29.9002%; height: 20px; text-align: center;">&nbsp;</td></tr></tbody></table>

x = uses **address 200**, where the value 3 is stored      y = uses **address 201**, where the value 5 is stored

z = uses **address 200**, where the value 3 is stored  

The variable keeps its name in memory along with an address, and the value keeps the value itself in memory.

If you write something like z = x, the two variables **share the same address in memory**.

So what happens if we change a value at this point?

\-Example code-

```html
let x = 3;   //primitive type
let y = 5;
let z = x;

z = 7;   //if you do this

console.log(x); // 3   *100
console.log(y); // 5   *101
console.log(z); // 7   *102
```

<table style="border-collapse: collapse; width: 99.5349%; height: 62px;" border="1" data-ke-style="style13"><tbody><tr style="height: 20px;"><td style="width: 16.1393%; height: 20px; text-align: center;">Address</td><td style="width: 27.1699%; height: 20px; text-align: center;">100</td><td style="width: 28.7975%; height: 20px; text-align: center;">101</td><td style="width: 27.8933%; height: 20px; text-align: center;">102</td></tr><tr style="height: 20px;"><td style="width: 16.1393%; height: 20px; text-align: center;"><span style="color: #333333;">Memory</span></td><td style="width: 27.1699%; height: 20px; text-align: center;">x = *200</td><td style="width: 28.7975%; height: 20px; text-align: center;"><span style="color: #333333;">y = *201</span></td><td style="width: 27.8933%; height: 20px; text-align: center;"><span style="color: #333333;">z = *202</span></td></tr></tbody></table>

<table style="letter-spacing: 0px; border-collapse: collapse; width: 99.3644%; height: 75px;" border="1" data-ke-style="style15"><tbody><tr style="height: 20px;"><td style="width: 16.5819%; text-align: center; height: 20px;">Address</td><td style="width: 27.0629%; text-align: center; height: 20px;">200</td><td style="width: 28.0304%; text-align: center; height: 20px;">201</td><td style="width: 28.2085%; text-align: center; height: 20px;">202</td></tr><tr style="height: 21px;"><td style="width: 16.5819%; text-align: center; height: 21px;"><span>Memory</span></td><td style="width: 27.0629%; text-align: center; height: 21px;">3</td><td style="width: 28.0304%; text-align: center; height: 21px;">5</td><td style="width: 28.2085%; text-align: center; height: 21px;">7</td></tr></tbody></table>

x = uses **address 200**, where the value 3 is stored      y = uses **address 201**, where the value 5 is stored

z = uses **address 202**, where the value 7 is stored  

With a primitive type, changing z's value puts the new value in a new memory slot and z uses that address.

**Reference types**, however, work differently.

\-Example code-

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

<table style="letter-spacing: 0px; border-collapse: collapse; width: 100%; height: 40px;" border="1" data-ke-style="style13"><tbody><tr style="height: 20px;"><td style="width: 14.3951%; height: 20px; text-align: center;">Address</td><td style="width: 28.7978%; height: 20px; text-align: center;">100</td><td style="width: 28.9138%; height: 20px; text-align: center;">101</td><td style="width: 27.8933%; height: 20px; text-align: center;">102</td></tr><tr style="height: 20px;"><td style="width: 14.3951%; height: 20px; text-align: center;"><span>Memory</span></td><td style="width: 28.7978%; height: 20px; text-align: center;">obj = *200~*201</td><td style="width: 28.9138%; height: 20px; text-align: center;"><span>copy = *200~*201</span></td><td style="width: 27.8933%; height: 20px; text-align: center;">&nbsp;</td></tr></tbody></table>

<table style="letter-spacing: 0px; border-collapse: collapse; width: 100%; height: 40px;" border="1" data-ke-style="style15"><tbody><tr style="height: 20px;"><td style="width: 14.3951%; height: 20px; text-align: center;">Address</td><td style="width: 28.6815%; height: 20px; text-align: center;">200</td><td style="width: 29.2627%; height: 20px; text-align: center;">201</td><td style="width: 27.6607%; height: 20px; text-align: center;">202</td></tr><tr style="height: 20px;"><td style="width: 14.3951%; height: 20px; text-align: center;"><span>Memory</span></td><td style="width: 28.6815%; height: 20px; text-align: center;">a = *300</td><td style="width: 29.2627%; height: 20px; text-align: center;">b = *301</td><td style="width: 27.6607%; height: 20px; text-align: center;">&nbsp;</td></tr></tbody></table>

<table style="letter-spacing: 0px; border-collapse: collapse; width: 100%; height: 39px;" border="1" data-ke-style="style12"><tbody><tr style="height: 19px;"><td style="width: 14.5349%; height: 19px; text-align: center;">Address</td><td style="width: 28.9535%; height: 19px; text-align: center;">300</td><td style="width: 28.721%; height: 19px; text-align: center;">301</td><td style="width: 27.6744%; height: 19px; text-align: center;">302</td></tr><tr style="height: 20px;"><td style="width: 14.5349%; height: 20px; text-align: center;"><span>Memory</span></td><td style="width: 28.9535%; height: 20px; text-align: center;">10</td><td style="width: 28.721%; height: 20px; text-align: center;">21</td><td style="width: 27.6744%; height: 20px; text-align: center;">&nbsp;</td></tr></tbody></table>

Did you catch it?

With a primitive type, changing the value created it in a new memory slot. But with a reference type,

changing the value on copy changed the original object too.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/79/img_2.webp)

Let me explain why in a way that's easy to follow. It helps to code along while looking at the tables below.

<table style="border-collapse: collapse; width: 100%; height: 40px;" border="1" data-ke-style="style13"><tbody><tr style="height: 20px;"><td style="height: 20px; width: 10.9302%; text-align: center;">Address</td><td style="height: 20px; width: 25.4651%; text-align: center;">100</td><td style="height: 20px; width: 33.3721%; text-align: center;">101</td><td style="height: 20px; width: 30.1163%; text-align: center;">102</td></tr><tr style="height: 20px;"><td style="height: 20px; width: 10.9302%; text-align: center;"><span style="color: #333333;">Memory</span></td><td style="height: 20px; width: 25.4651%; text-align: center;">obj = *200~*201</td><td style="height: 20px; width: 33.3721%; text-align: center;"><span style="color: #333333;">copy = *200~*201</span></td><td style="height: 20px; width: 30.1163%; text-align: center;">&nbsp;</td></tr></tbody></table>

<table style="border-collapse: collapse; width: 100%; height: 40px;" border="1" data-ke-style="style15"><tbody><tr style="height: 20px;"><td style="height: 20px; width: 10.4651%; text-align: center;">Address</td><td style="height: 20px; width: 26.3953%; text-align: center;">200</td><td style="height: 20px; width: 33.0233%; text-align: center;">201</td><td style="height: 20px; width: 30%; text-align: center;">202</td></tr><tr style="height: 20px;"><td style="height: 20px; width: 10.4651%; text-align: center;"><span style="color: #333333;">Memory</span></td><td style="height: 20px; width: 26.3953%; text-align: center;">a = *300</td><td style="height: 20px; width: 33.0233%; text-align: center;">b = *301</td><td style="height: 20px; width: 30%; text-align: center;">&nbsp;</td></tr></tbody></table>

<table style="border-collapse: collapse; width: 100%; height: 40px;" border="1" data-ke-style="style12"><tbody><tr style="height: 20px;"><td style="width: 10.4651%; height: 20px; text-align: center;">Address</td><td style="width: 26.6279%; height: 20px; text-align: center;">300</td><td style="width: 32.5581%; height: 20px; text-align: center;">301</td><td style="width: 30.2326%; height: 20px; text-align: center;">302</td></tr><tr style="height: 20px;"><td style="width: 10.4651%; height: 20px; text-align: center;"><span style="color: #333333;">Memory</span></td><td style="width: 26.6279%; height: 20px; text-align: center;">10</td><td style="width: 32.5581%; height: 20px; text-align: center;">21 -&gt; 0</td><td style="width: 30.2326%; height: 20px; text-align: center;">&nbsp;</td></tr></tbody></table>

We changed **copy.b** to 0. In other words, we changed the value at **201**, so **301** becomes 0.

Meanwhile **100** and **101** know nothing about it and just **keep their addresses**. We only changed copy.b, which only changes the value at that address.

So 301 becomes 0, and the original ends up showing **object.b** as **0** too.

### **\-Conclusion-**

We often work on a copy to **preserve the original**, so this becomes a **big problem**, right?

That's why people say to **maintain immutability** \= (changing the copy must not change the original)

to prevent this kind of **mishap**.

I hope this gave you a simple understanding of **JavaScript immutability**. Happy, diligent coding.
