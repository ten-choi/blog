---
title: "Understanding the Monotonic Stack Clearly"
labels: ["Algorithm","Data Structure","Stack","CodingTest","Monotonic Stack","Archive"]
published: true
date: 2025-07-28T11:20:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "8823034553767211470"
source: "archive"
---

# Understanding the Monotonic Stack Clearly

## Definition

A monotonic stack is **a stack managed so that its elements always stay in ascending or descending order**.

It's not a separate data structure. It's just a regular stack with one extra rule. Hearing only that much, it already sounds really easy.

> Before pushing, pop every element that would break the sort order. Then push.

## What Problems Does It Solve

Problems where, for each element of an array, you need to find:

- **Next greater element**: the first element to the right that's greater than it
- **Next smaller element**: the first element to the right that's smaller than it
- **Previous greater/smaller element**: the same question, looking left

Solving these with a nested loop is O(N²). A monotonic stack solves them in O(N).
The more data you have, the more this kind of efficiency matters.


## How It Works

I'll explain with the "next greater element" problem. There are only two rules.

1. Traverse the array from the left. The stack holds **the indices of elements that haven't found their answer yet**.
2. If a new element `x` is greater than the value at the top of the stack → the top's answer is `x`. **Its answer is settled, so pop it.** Repeat until the top is greater than `x` or the stack is empty, then push `x`.

Let's trace `[2, 1, 4, 3]` by hand. (The stack holds indices, but I'll show values to make it easier to follow.)

| Step | Current value | Action | Stack (bottom→top) | Settled answers |
| --- | --- | --- | --- | --- |
| 1 | 2 | Stack is empty → push | [2] | |
| 2 | 1 | 1 < 2 → just push | [2, 1] | |
| 3 | 4 | 4 > 1 → pop, 4 > 2 → pop, push | [4] | 1→4, 2→4 |
| 4 | 3 | 3 < 4 → just push | [4, 3] | |
| End | | Elements left in the stack have no answer | | 4→-1, 3→-1 |

Result: `[4, 4, -1, -1]`

Two things stand out here.

- The stack always stays in descending order (4, 3), because elements that would break the order are removed before the push.
- **A popped element's answer is settled the moment it's popped.** You never need to look at it again.

## Why It's O(N)

Each element is pushed exactly once and popped at most once, so the total number of operations is at most 2N. Even though the while loop is nested, it's not O(N²).
This sounds like nonsense at first, so you'll need to look at it a few times before it clicks.


## Implementation

```python
def next_greater(nums):
    n = len(nums)
    result = [-1] * n   # -1 if there's no answer
    stack = []          # stores indices

    for i in range(n):
        # pop while nums[i] settles the answer for the stack top
        while stack and nums[stack[-1]] < nums[i]:
            idx = stack.pop()
            result[idx] = nums[i]
        stack.append(i)

    return result

print(next_greater([2, 1, 4, 3]))  # [4, 4, -1, -1]
```

Why **store indices** rather than values: if the problem asks "how many positions later is it," you need the index. You can always get the value with `nums[index]`, so storing indices is always more flexible.


## Application: Daily Temperatures (LeetCode 739)

For each day, find "how many days until a warmer day." Just change the value you store as the answer in the code above from `nums[i]` to `i - idx` (the index difference) and you're done.

```python
def daily_temperatures(temps):
    answer = [0] * len(temps)
    stack = []

    for i, t in enumerate(temps):
        while stack and temps[stack[-1]] < t:
            idx = stack.pop()
            answer[idx] = i - idx   # how many days later
        stack.append(i)

    return answer
```

## Summary of Directions

What you're looking for and the stack's sort direction are **opposite**.

| Looking for | Stack to maintain | Pop condition |
| --- | --- | --- |
| Next/previous **greater** element | **Descending** stack | `stack top value < current value` |
| Next/previous **smaller** element | **Ascending** stack | `stack top value > current value` |

No need to memorize this; it follows from the pop condition. "Find a greater element" = "pop when the current value is greater" = smaller values get removed, so only larger values in order (descending) remain on the stack.

## Things to Watch Out For

- **`<` vs `<=`**: the inequality depends on whether equal values count as an answer. Check the problem's conditions.
- **Elements left on the stack after the traversal**: these are elements with no answer. Leave them at whatever default the problem asks for, like `-1` or `0`.

## Wrap-Up

- Problems that find the "next/previous greater or smaller element" in an array → monotonic stack.
- Rule: when a new element breaks the stack's order, pop the elements it breaks and settle their answers.
- Each element is pushed once and popped at most once → O(N).

This one template carries you through Next Greater Element (496), Daily Temperatures (739), Stock Span (901), and Largest Rectangle in Histogram (84).
