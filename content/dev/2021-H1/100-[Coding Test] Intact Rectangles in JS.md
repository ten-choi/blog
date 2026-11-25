---
title: "[Coding Test] Intact Rectangles in JS"
labels: ["CodingTest","Archive"]
published: true
date: 2021-05-23T14:24:10+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 100
tistoryUrl: "https://yeolceo.tistory.com/100"
tistoryCategory: "CodingTest"
tistoryTags: ["코딩테스트","멀쩡한"]
tistoryPostedAt: "2021-05-23 14:24:10"
language: en
bloggerPostId: "2970455060534381053"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/100/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/100/img_1.webp)

The key to the "intact rectangles" problem is the greatest common divisor (GCD).

Example -> let's work out how 8 and 12 give us 80.

The GCD of 8 and 12 is 4, which means the shape repeats 4 times. What does that mean?

If you divide each side by the GCD you get 2 and 3, so a shape that spans 2 cells by 3 cells appears 4 times.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/100/img_2.webp)

If we had 6 and 2 instead, the GCD is 2, so the same pattern shows up twice.

Same idea here: divide the width and height by the GCD and you get a 3-by-1 shape, repeated GCD times.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/100/img_3.webp)

By now you should get the idea of the pattern. But to solve the problem, we need the number of squares we can't use.

So take the 1-by-3 shape as an example: what happens when you draw the diagonal?

If you draw a diagonal across a rectangle 1 cell wide and 3 cells tall, it cuts through every cell.

Here you have to think in terms of unit squares: the vertical side is three 1x1 squares, and the horizontal side is one 1x1 square.

In other words, the vertical squares already include a base horizontal cell.

So it's the 3 vertical cells the line passes through + the horizontal cells,

and the number of squares the diagonal cuts can be computed as: vertical cells (3) + horizontal cells (1) - the shared base cell (1).

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/100/img_4.webp)

To make this clearer, let's go back to the original example.

The GCD in the example is 4, so we get four 2-by-3 rectangles, i.e. 2 wide and 3 tall.

In the 1-by-3 case above, the line simply cuts all 3 vertical cells. But here there are 2 horizontal cells.

That means the line shifts over by one cell along the way, so we have to add +1 for each place where it crosses over.

So what do we get? -> vertical cells (3) + horizontal cells (2) - the base vertical cell (1).

With 3 tall and 1 wide, the line would cut 3 cells; but since the width grew by 1, there's always a spot where the line moves over a column and cuts 2 cells in the same row.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/100/img_5.webp)

Now for the solution. If the pattern above didn't click, my explanation may have fallen short, so please make sure you understand

that pattern from somewhere before looking at the answer below.

The code itself is simple. We plug in w or h and find the GCD.

Write a for loop that starts at the max value of one of them and counts down with --.

As the value decreases, the first one that divides both with a remainder of 0 (using %) is the GCD.

(If you want to be more efficient by starting the loop from the smaller value, just add an if statement.)

Let's follow the problem -> we return **total cells - cut cells**, and the formula for cut cells is exactly the pattern explained above.

(width/GCD + height/GCD - 1) = horizontal cells + vertical cells - base cell. That's the idea.

Then we multiply by the GCD, since that's how many times the pattern repeats.

```html
function solution(w, h) {
    for(let i =w; 0<i; i--){
        if(w%i==0 && h%i==0)return (w*h)-((w/i+h/i-1)*i)
    }
}
```

When i is the GCD, it passes the if statement and returns the answer. Happy coding.
