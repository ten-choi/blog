---
title: "LeetCode 62: Unique Paths - A DP Approach"
labels: ["Algorithm","Dynamic Programming","DP","LeetCode","CodingTest","Archive"]
published: true
date: 2025-05-20T16:07:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "5789872983727885290"
source: "archive"
archivePath: "_archive/dev/algorithms/leetcode/62. Unique Paths.md"
---

# Unique Paths (LeetCode 62)

This is a classic dynamic programming (DP) problem.  
DP is a way of solving problems efficiently by storing the results of repeated calculations.

At first I solved it with the permutation formula (combinatorics). But that approach can overflow on large inputs, so it isn't the best option.

## Approach 1: Combinatorics (Permutations)

```kotlin
/**
 * Extension function that computes the factorial of an integer
 * @return the factorial (as a Long)
 */
fun Int.factorial(): Long {
    var result = 1L
    for (i in 2..this) {
        result *= i
    }
    return result
}

class Solution {
    /**
     * Counts the unique paths from the start to the end (permutation approach)
     * Formula: (m+n-2)! / ((m-1)! * (n-1)!)
     * @param m number of rows in the grid
     * @param n number of columns in the grid
     * @return number of possible paths
     */
    fun uniquePaths(m: Int, n: Int): Int {
        val numerator = (m + n - 2).factorial()
        val denominator = (m - 1).factorial() * (n - 1).factorial()
        return (numerator / denominator).toInt()
    }
}
```

You can solve it with factorials as above, but this problem is really meant to be solved with DP (dynamic programming), which is more efficient.

## Approach 2: Dynamic Programming (DP)

```kotlin
class Solution {
    /**
     * Counts the unique paths from the start to the end (DP approach)
     * The number of paths to each cell is the sum of the paths coming from the left and from above
     * @param m number of rows in the grid
     * @param n number of columns in the grid
     * @return number of possible paths
     */
    fun uniquePaths(m: Int, n: Int): Int {
        val dp = IntArray(n) { 1 } // Initialize the whole first row to 1
        for (i in 1 until m) {
            for (j in 1 until n) {
                dp[j] += dp[j - 1] // current cell = paths from above + paths from the left
            }
        }
        return dp[n - 1]
    }
}
```

## How the DP Approach Works

The table below shows the number of paths to each cell for m=3, n=7:

| (i,j) | Col 0 | Col 1 | Col 2 | Col 3 | Col 4 | Col 5 | Col 6 |
| ----- | --- | --- | --- | --- | --- | --- | --- |
| Row 0 | 1   | 1   | 1   | 1   | 1   | 1   | 1   |
| Row 1 | 1   | 2   | 3   | 4   | 5   | 6   | 7   |
| Row 2 | 1   | 3   | 6   | 10  | 15  | 21  | 28  |

### An Intuitive Look at DP

Let's walk through some concrete examples to see how the DP approach works:

1. **Cell (1,2):**

   - The value at (1,2) is 3.
   - That's the value above it at (0,2), which is 1, plus the value to its left at (1,1), which is 2.
   - So 3 = 1 + 2.

2. **Cell (2,2):**
   - The value at (2,2) is 6.
   - That's the value above it at (1,2), which is 3, plus the value to its left at (2,1), which is 3.
   - So 6 = 3 + 3.

### Why Calculate It This Way?

There are 6 ways to reach (2,2) because:

- There are 3 paths to (1,2), and from each of them, moving one step down reaches (2,2).
- There are 3 paths to (2,1), and from each of them, moving one step right reaches (2,2).
- These two sets of paths don't overlap, so the total is 3 + 3 = 6.

This is how dynamic programming avoids redundant work: it stores previously computed results and reuses them to solve the problem efficiently.
