---
title: "Why Use async and await? A Simple Explanation with JS"
labels: ["TS","JS","javascript","synchronous","ES6","async","Archive"]
published: true
date: 2020-05-21T15:22:37+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 4
tistoryUrl: "https://yeolceo.tistory.com/4"
tistoryCategory: "TS, JS/javascript"
tistoryTags: ["동기","ES6","async","javascript"]
tistoryPostedAt: "2020-05-21 15:22:37"
language: en
bloggerPostId: "2415606083592551923"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/4/img.webp)

## **\- What Are Synchronous & Asynchronous?**

First, to make things easier, let me explain synchronous and asynchronous in very simple terms!

Synchronous means things run at the same time. Asynchronous, as the name suggests, means they don't run at the same time.

## **\- How to Use async & await**

async is short for asynchronous, and await means "to wait (for something)."

First, create an async function. As shown below, where the keyword goes depends on whether it's an arrow function or a regular function.

```html
async asyncAPI function(){    //regular function syntax

}

asyncAPI = async () =>{       //arrow function syntax

}
```

async/await is also ES6, so I'll use an ES6 arrow function for the example.

```html
let num =1;
function add(){
	num+=1;
    return num;
}

asyncAPI = async () =>{

	await console.log(num);
	await console.log(add());
	await console.log(num+1); 
}
```

My intent here is for 1, 2, 3 to be printed in order. If the add function were really long code and ran synchronously,  
the third console call would run first and you'd get 1, 2, 2 in the console.

```html
let num = 1;
asyncAPI = async () =>{

	console.log(num);
    let add = await db.getconnect().query(String)[0];//example code that fetches a value from the DB
	num += add; //if add is 1
    console.log(num);
	console.log(num+1); 
}
```

The code above should show you, in a simple way, why this needs to be synchronous and how sync and async differ. If your code absolutely has to run in order, you need to apply async handling. You can't let the next line run while the DB call is still in progress and then do math on a value that doesn't exist yet.

Some of you might think of setTimeout from a different angle and try something like this:

```html
asyncAPI = async () =>{

  await setTimeout( ()=>{ console.log( 1); }  ,  2000 ); 

  console.log( 2) ; 

}
```

You'd expect 1 and then 2 in the console, but setTimeout doesn't return a Promise internally, so it won't behave the way you want.

A Promise here is the JavaScript object for handling asynchronous work that async uses under the hood.

async returns a Promise. So you can also handle things asynchronously by calling then on the Promise.

You might ask, "Then why not just use Promises? Why bother with async/await?" Because async/await is more concise to write than Promise.then.

I'd recommend studying Promises and then as well. That was async/await in JavaScript. Happy coding.
