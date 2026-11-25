---
title: "[ Node ] What Is the Node Event Loop"
labels: ["TS","JS","nodejs","JavaScript","node","EventLoop","libuv","Archive"]
published: true
date: 2022-04-07T12:14:45+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 130
tistoryUrl: "https://yeolceo.tistory.com/130"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["JavaScript","node","nodejs","EventLoop","libuv"]
tistoryPostedAt: "2022-04-07 12:14:45"
language: en
bloggerPostId: "6185108960706734847"
---
#### Overview

While working with Node, let's look at the **[Node event loop](https://nodejs.org/ko/docs/guides/event-loop-timers-and-nexttick/)**. I leaned heavily on the official docs.  
If you don't know the JavaScript event loop yet, this video is a good one to watch. **[Link](https://www.youtube.com/watch?v=QFHyPInNhbo&ab_channel=%EC%9A%B0%EB%A6%AC%EB%B0%8B_woorimIT)**

#### Contents

-   What is Node
-   Node Event Loop basics
-   Node Event Loop in depth

## **\- What Is Node**

Node is a JavaScript runtime built on Chrome's V8 JavaScript engine.

It's single-threaded and works asynchronously, using event-driven, non-blocking I/O.

## **\- Node Event Loop Basics**

Even though JavaScript is single-threaded, Node's event loop lets Node.js perform non-blocking I/O operations by offloading work to the system kernel whenever possible.

Most modern kernels are multi-threaded, so they can run multiple operations in the background. When one of these operations completes, the kernel tells Node.js so that the appropriate callback can be added to the **poll** queue and eventually executed.

![https://nodejs.org/ko/docs/guides/event-loop-timers-and-nexttick/  (image from the official Node site)](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/130/img.webp)

## Phases Overview

-   **timers**: this phase runs callbacks scheduled by setTimeout() and setInterval().
-   **pending callbacks**: runs I/O callbacks deferred to the next loop iteration.
-   **idle, prepare**: only used internally.
-   **poll**: retrieves new I/O events and runs I/O-related callbacks (almost all callbacks except close callbacks, those scheduled by timers, and setImmediate()). Node will block here when appropriate.
-   **check**: setImmediate() callbacks are invoked here.
-   **close callbacks**: some close callbacks, e.g. socket.on('close',...).

Between each run of the event loop, Node.js checks whether it's waiting on any other asynchronous I/O or timers, and shuts down cleanly if there's nothing left.

## **\- Node Event Loop in Depth**

1\. timers

A timer doesn't fire at an exact time; it specifies a threshold, and the callback is scheduled to run after that.  
For example, if you have a timer set for 1 second and a 0.95-second callback is running, the timer runs after that callback.  
If that callback actually takes 0.1 seconds longer, the timer would fire at around 1.05 seconds. In other words, timers can be a bit imprecise.  
The timers phase runs as soon as possible once the threshold passes, and since the poll phase hogging all resources would affect the timers phase, libuv controls the poll phase to prevent that.

2\. pending callbacks: This phase executes callbacks for some system operations such as types of TCP errors. For example, if a TCP socket receives ECONNREFUSED when attempting to connect, some \*nix systems want to wait to report the error. This will be queued to execute in the **pending callbacks** phase - official docs

Apart from TCP cases like the above, when I/O deferred by a loop iteration completes, the result goes into the queue. For example, according to [this article](https://nexocode.com/blog/posts/behind-nodejs-event-loop/), callbacks after file read/write operations or completed network operations end up in pending callbacks. I think it's similar to how things move from the Web APIs to the queue in the JS event loop.

3\. idle, prepare: These are only used internally, so I'll skip them.

4\. poll: Retrieves new I/O events and runs I/O-related callbacks.

The **poll** phase has two main functions:

1.  Calculating how long it should block and poll for I/O, then
2.  Processing events in the **poll** queue.

When the event loop enters the **poll** phase and there are no timers scheduled, one of two things happens:

-   If the **poll** queue is **not empty**, the event loop iterates through its queue of callbacks, executing them synchronously until either the queue is exhausted or a system-dependent hard limit is reached.

-   If the **poll** queue **is empty**, one of the following happens:
    -   If scripts have been scheduled by setImmediate(), the event loop ends the **poll** phase and moves on to the **check** phase to run those scheduled scripts.
    -   If scripts have not been scheduled by setImmediate(), the event loop waits for callbacks to be added to the queue, then runs them immediately.

Like the JS call stack, if callback functions are piled up, poll keeps running until they're all done.  
Once the **poll** queue is empty, the event loop checks for timers whose time thresholds have been reached. If one or more timers are ready, the event loop wraps back to the **timers** phase to run those timers' callbacks.

5\. check: setImmediate() callbacks are invoked here. After the previous phases, the check phase runs. Normally timers would run first, but in Node,

if both functions are called from within the main module, the timing is **bound by the performance of the process**. For example, if you run the following script, the order in which the two timers run is non-deterministic. \- [Reference](https://velog.io/@adam2/Node.js-%ED%95%B4%EB%B6%80%ED%95%99-2-%EC%9D%B4%EB%B2%A4%ED%8A%B8-%EB%A3%A8%ED%94%84-phase)

```html
setTimeout(function() {
    console.log('setTimeout')
}, 0);
setImmediate(function() {
    console.log('setImmediate')
});
```

6\. close callbacks: Some close callbacks. Between runs of the event loop, Node.js checks whether it has any other async work, I/O, or timers  
pending, and shuts down cleanly if not.

At the end of each phase, the nextTickQueue and microTaskQueue are processed.

According to the Node.js docs, "the nextTickQueue will be processed after the current operation is completed, regardless of the current phase of the event loop."

For the timers phase, Node before v11 behaved differently from the browser (which is also a JS runtime), but apparently it's been aligned again. - [Reference](https://blog.insiderattack.net/new-changes-to-timers-and-microtasks-from-node-v11-0-0-and-above-68d112743eb3)

Event callbacks are queued in the nextTickQueue.

Promises are queued in the microTaskQueue.

idle and prepare aren't covered much in the docs either, so I'll skip them.

Let's run some code and test it.

```html
setImmediate(() => console.log('this is set immediate 1'));
setImmediate(() => console.log('this is set immediate 2'));
setImmediate(() => console.log('this is set immediate 3'));

setTimeout(() => console.log('this is set timeout 1'), 0);
setTimeout(() => {
    console.log('this is set timeout 2');
    process.nextTick(() => console.log('this is process.nextTick added inside setTimeout'));
}, 0);
setTimeout(() => console.log('this is set timeout 3'), 0);
setTimeout(() => console.log('this is set timeout 4'), 0);
setTimeout(() => console.log('this is set timeout 5'), 0);

process.nextTick(() => console.log('this is process.nextTick 1'));
process.nextTick(() => {
    process.nextTick(console.log.bind(console, 'this is the inner next tick inside next tick'));
});
process.nextTick(() => console.log('this is process.nextTick 2'));
process.nextTick(() => console.log('this is process.nextTick 3'));
process.nextTick(() => console.log('this is process.nextTick 4'));

function callBack1(){ console.log('this is function 1')}
function callBack2(){ 
    console.log('this is function 2')
    callBack4();
    process.nextTick(() => console.log('this is function 2 of process.nextTick 1'));
}
function callBack3(){ console.log('this is function 3')}
function callBack4(){ console.log('this is function 4')}

callBack1()
callBack2()
callBack3()
```

It's easy to understand if you think of it this way: the call stack in the JavaScript event loop is similar to poll, and Node just splits things into more categories to handle async work.

The official docs explain it cleanly and I didn't have much to add, so a lot of this is copied from there.

Check the official docs, read up on the JS event loop, and if that's not enough, **[this article](https://www.korecmblog.com/node-js-event-loop/)** should help.

Well-grounded advice is always welcome. Happy coding, and keep at it.
