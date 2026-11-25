---
title: "What I Learned About JS Syntax and ES6"
labels: ["TS","JS","javascript","ES6","Archive"]
published: true
date: 2020-08-12T15:08:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 39
tistoryUrl: "https://yeolceo.tistory.com/39"
tistoryCategory: "TS, JS/javascript"
tistoryTags: ["ES6","js"]
tistoryPostedAt: "2020-08-12 15:08:11"
language: en
bloggerPostId: "2440555935271716949"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/39/img.webp)

**ECMAScript** (or ES[\[1\]](https://ko.wikipedia.org/wiki/ECMA%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8#cite_note-1)) is a standardized [scripting language](https://ko.wikipedia.org/wiki/%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8_%ED%94%84%EB%A1%9C%EA%B7%B8%EB%9E%98%EB%B0%8D_%EC%96%B8%EC%96%B4) defined by the **ECMA-262** specification from [Ecma International](https://ko.wikipedia.org/wiki/Ecma_%EC%9D%B8%ED%84%B0%EB%82%B4%EC%85%94%EB%84%90). It was created to standardize [JavaScript](https://ko.wikipedia.org/wiki/%EC%9E%90%EB%B0%94%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8), which is still its best-known implementation, but it also covers others such as [ActionScript](https://ko.wikipedia.org/wiki/%EC%95%A1%EC%85%98%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8) and [JScript](https://ko.wikipedia.org/wiki/J%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8).[\[2\]](https://ko.wikipedia.org/wiki/ECMA%EC%8A%A4%ED%81%AC%EB%A6%BD%ED%8A%B8#cite_note-2) ECMAScript is widely used for client-side scripting on the [web](https://ko.wikipedia.org/wiki/%EC%9B%94%EB%93%9C_%EC%99%80%EC%9D%B4%EB%93%9C_%EC%9B%B9), and it's increasingly used for server applications and services built with [Node.js](https://ko.wikipedia.org/wiki/Node.js).

That's how the wiki puts it.

For reference, ES2015 is ES6, and ES5 is the one before it. JS versions are named by year like that from then on (2016 is ES7).

Apparently the \` (backtick) became usable starting with ES6. I'd just been using it without knowing the difference.

It's well known that we went from having only `var` to also having `const` and `let`, which brought block scope.

```html
var object = {                           |     const object6 = {

  name : name ,                          |             name,

  age : age                              |             age ,

                                         |     ['es'+6]: 'Now you can declare computed property names inline like this'

}                                        |     }

object['es'+5] = 'Back then you had to declare it separately';  |
```

The right side is ES6. When the variable you're assigning has the same name as the property, you can use the shorthand on the right.

Arrow functions (ES6) are used so that `this` is determined by where the function is defined, which saves you from calling `bind`. That's enough of the famous stuff for now.

The snippets below are taken from MDN. They're about JS destructuring of objects and arrays.

var \[a, ...b\] \= \[1, 2, 3\];

console.log(a);console.log(b);  // values: 1 and [2, 3] - this works

var o \= {p: 42, q: true};

var {p, q} \= o; console.log(p);

// 42 console.log(q); // true 

 1.  var a, b;           ({a, b} \= {a: 1, b: 2}); This works.

 2. var a, b;        {a, b} \= {a: 1, b: 2} ; This doesn't. The left-hand side is treated as a block, not an object.

**Note**: The parentheses ( ... ) around the assignment statement are required when using object literal destructuring assignment without a declaration.  
That's what MDN says. In other words, wrapping the statement in parentheses makes it count as an object literal instead of a block.

If you learned JS from searches or online courses rather than a book, this kind of knowledge about objects should come in pretty handy.

[https://developer.mozilla.org/ko/docs/Web/JavaScript/Reference/Operators/Destructuring\_assignment](https://developer.mozilla.org/ko/docs/Web/JavaScript/Reference/Operators/Destructuring_assignment)
