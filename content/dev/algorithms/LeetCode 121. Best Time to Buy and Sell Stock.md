---
title: "LeetCode 121. Best Time to Buy and Sell Stock - One-Pass O(n) Solution Explained"
labels: ["LeetCode", "Algorithm", "Array", "Coding Interview", "Kadane's Algorithm", "Java"]
published: true
date:
readerComments: "ALLOW"
bloggerPostId: "6814840581475176308"
---


## Problem

You are given an array `prices` where `prices[i]` is the price of a stock on day `i`.
Choose one day to buy and a **later** day to sell to maximize your profit.
Return the maximum profit. If no profit is possible, return `0`.

```
Input:  prices = [7,1,5,3,6,4]
Output: 5      → buy on day 1 (price 1), sell on day 4 (price 6)
```

**Constraints**
- `1 <= prices.length <= 10^5`
- `0 <= prices[i] <= 10^4`

---

## How I'd explain it in an interview

### 1. Clarify first

- Exactly **one** transaction: one buy, then one sell.
- Sell day must be **after** the buy day.
- If prices only go down → return `0`, never a negative number.
- Length is at least 1, so `prices[0]` is always safe to read.

### 2. Why brute force fails

Try every pair `(i, j)` with `i < j` → O(n²).
With `n = 10^5` that's ~10^10 operations → TLE. We need O(n).

### 3. Key insight

> The best profit from selling **today** = `prices[i] − (lowest price seen so far)`

So one pass is enough. Keep only **two variables**:

1. `minPrice` – lowest price so far (best day to buy)
2. `maxProfit` – best profit so far

Each day, in this order:
1. Update `maxProfit` with `prices[i] − minPrice`
2. Update `minPrice` if today is cheaper

Updating `maxProfit` **first** means we never "buy and sell on the same day".

### 4. Walkthrough — `[7,1,5,3,6,4]`

| Day | Price | Sell today?  | maxProfit | minPrice |
|-----|-------|--------------|-----------|----------|
| 0   | 7     | –            | 0         | 7        |
| 1   | 1     | 1 − 7 = −6   | 0         | 1        |
| 2   | 5     | 5 − 1 = 4    | 4         | 1        |
| 3   | 3     | 3 − 1 = 2    | 4         | 1        |
| 4   | 6     | 6 − 1 = 5    | **5**     | 1        |
| 5   | 4     | 4 − 1 = 3    | 5         | 1        |

---

## Solution

### Version 1 – explicit `if`

```java
class Solution {
    public int maxProfit(int[] prices) {
        int maxProfit = 0;          // 0 if no profit is possible
        int minPrice = prices[0];   // safe: length >= 1

        for (int i = 1; i < prices.length; i++) {
            if (prices[i] - minPrice > maxProfit) {   // 1) sell today?
                maxProfit = prices[i] - minPrice;
            }
            if (prices[i] < minPrice) {               // 2) cheaper day to buy?
                minPrice = prices[i];
            }
        }
        return maxProfit;
    }
}
```

### Version 2 – `Math.max` / `Math.min` (what I'd write in an interview)

Same logic, but reads like a sentence: *"best so far = max(what I had, what I'd get today)"*.

```java
class Solution {
    public int maxProfit(int[] prices) {
        int minPrice = Integer.MAX_VALUE;  // alternative init: no need to special-case prices[0]
        int maxProfit = 0;

        for (int price : prices) {
            maxProfit = Math.max(maxProfit, price - minPrice);  // sell today?
            minPrice  = Math.min(minPrice, price);              // cheaper day to buy?
        }
        return maxProfit;
    }
}
```

> `Integer.MAX_VALUE` note: on day 0, `price − minPrice` is a big negative number, which `Math.max(0, …)` simply ignores. So it's safe.

---

## Complexity

- **Time O(n)** – single pass
- **Space O(1)** – two ints

---

## Follow-ups

| Question | Answer |
|----------|--------|
| Multiple transactions? | LC 122 – sum every positive `prices[i] − prices[i−1]` |
| At most k transactions? | LC 123 / 188 – DP with a state per transaction count |
| Fee or cooldown? | LC 714 / 309 – DP with `hold` / `notHold` states |
| Return buy/sell days too? | Save the index when `minPrice` updates; record `(buyIdx, i)` when `maxProfit` updates |

**Pattern:** this is **Kadane's algorithm** on the daily differences `prices[i] − prices[i−1]` — max subarray sum = max profit.
