---
title: "10-Week Coding Test Plan for Backend Roles at English-Speaking Tech Companies in Tokyo (Java)"
labels: ["Algorithm","LeetCode","Archive"]
published: true
date: 2025-05-01T12:55:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "2299301214046208501"
source: "archive"
archivePath: "_archive/dev/algorithms/leetcode/0문제유형.md"
---
# 10-Week Coding Test Plan for Backend Roles at English-Speaking Tech Companies in Tokyo (Java)
> Targets: Rakuten, PayPay, Mercari (+ prep for expanding to Amazon / Google Japan)
> Goal: reliably solve LeetCode Mediums within 45 minutes / for Mercari, get every Medium fully correct + good code quality
> Duration: 10 weeks / 2 hours on weekdays + mock tests on weekends
> ⭐ = problem confirmed to have actually been asked

---

## 0. Evidence (Test Formats)

| Company | Format | Source |
|---|---|---|
| PayPay | OA: 4 problems in 70 min, 2 Easy + 2 Medium. A perfect score isn't required. Then coding/LLD → system design → behavioral | [Glassdoor review](https://www.glassdoor.com/Interview/PayPay-Backend-Engineer-Interview-Questions-EI_IE3735809.0,6_KO7,23.htm) |
| PayPay | Actual OA problems: stack-based string manipulation (Easy) + the same problem as LC 2672. Watch boundary conditions / floating point | [LeetCode Discuss 2025.6](https://leetcode.com/discuss/interview-experience/6832936/), [LC Discuss (review comparing with Wise)](https://leetcode.com/discuss/interview-experience/1597982/PayPay-Japan-or-Wise-(Transfer-Wise)-Estonia-or-Offer) |
| PayPay | LC 1 and LC 34 actually asked in interviews. System design was about PayPay's own systems (bank integration, DB scaling) | [LeetCode Discuss](https://leetcode.com/discuss/post/1806599/PayPay-Japan-or-Entire-interview/) |
| PayPay | Heap-based + graph problems reported in interviews | [CodingKaro](https://www.codingkaro.in/jobs-internships/leetcode-interview-experience/PayPay) |
| Rakuten | OA: Codility, 2–3 problems, Easy–Medium. Then live coding + system design | [TechPrep 2026](https://www.techprep.app/blog/rakuten-interview-process) |
| Rakuten | Topics: sliding window / two pointers / hash maps, trees and graphs (BFS/DFS), basic DP | [Dataford 2026](https://dataford.io/interview-guides/rakuten/software-engineer) |
| Rakuten | Actually asked in interviews: Jump Game (LC 55), Generate Parentheses (LC 22), subarray sum, string compression | [Naukri review](https://www.naukri.com/code360/interview-experiences/rakuten-india/rakuten-interview-experience-by-veenit-kumar-off-campus-apr-2022), [GeeksforGeeks review](https://www.geeksforgeeks.org/rakuten-india-interview-experience-on-campus-2021/) |
| Mercari | OA: 3 problems in 60 min (Easy–Medium). 100% correctness expected + code quality (naming / clean code) evaluated | [Medium review 1](https://medium.com/@sonali122000/my-interview-experience-with-mercari-df2e27bca6ef) |
| Mercari | OA with all 3 problems Medium: priority queue, DP, bit manipulation. Modularity also evaluated. Most tech teams use English | [Medium review 2](https://medium.com/coderbyte/my-software-engineering-interview-experience-at-mercari-b9571d8a3969) |
| Mercari | India entity OA: one each of Easy/Medium/Hard; the Hard was graph + topological sort | [Medium review 3](https://dheeraj-bhagchandani.medium.com/mercari-india-sde-intern-backend-interview-experience-8f9f6f329351) |
| Mercari | Senior backend OA: 4 problems in 120 min, including a 0/1 knapsack type | [LeetCode Discuss](https://leetcode.com/discuss/interview-experience/5540416/Mercari-Senior-Backend-OA/) |

---

## 1. Daily Routine (2 Hours on Weekdays)

1. 1 new problem (45-minute cutoff — if you can't solve it, read the solution and retry from a blank page the next day)
2. 1 review problem (ones you got wrong 3 days / 1 week ago)
3. 10 minutes of pattern notes (one line on "which signal in the problem made me pick this pattern")

**Speed targets: Easy in 10 min / Medium in 30 min** (prep for PayPay's 4 problems in 70 min / Mercari's 3 problems in 60 min)

---

## 2. Problem List by Week

### Weeks 1–2: Speeding Up Familiar Patterns (Review Phase)

**Arrays & Hashing**
- [ ] ⭐ 1. Two Sum (actually asked in PayPay interviews)
- [ ] 217. Contains Duplicate
- [ ] 242. Valid Anagram
- [ ] 49. Group Anagrams
- [ ] 347. Top K Frequent Elements
- [ ] 238. Product of Array Except Self
- [ ] ⭐ 560. Subarray Sum Equals K (something similar asked in Rakuten interviews)
- [ ] 121. Best Time to Buy and Sell Stock

**Two Pointers / Sliding Window**
- [ ] 125. Valid Palindrome
- [ ] 15. 3Sum
- [ ] 11. Container With Most Water
- [ ] 3. Longest Substring Without Repeating Characters
- [ ] 424. Longest Repeating Character Replacement
- [ ] 209. Minimum Size Subarray Sum

**Stack (most frequent area in PayPay OAs)**
- [ ] 20. Valid Parentheses
- [ ] 155. Min Stack
- [ ] 739. Daily Temperatures
- [ ] ⭐ 2390. Removing Stars From a String (the "stack string manipulation" type from PayPay OAs)
- [ ] ⭐ 2672. Number of Adjacent Elements With the Same Color (actually asked in PayPay OAs)
- [ ] ⭐ 443. String Compression (type actually asked in Rakuten interviews)

**Binary Search**
- [ ] 704. Binary Search
- [ ] 33. Search in Rotated Sorted Array
- [ ] 153. Find Minimum in Rotated Sorted Array
- [ ] ⭐ 34. Find First and Last Position of Element (actually asked in PayPay interviews)

**Misc (PayPay OA simulation-style)**
- [ ] ⭐ 67. Add Binary (actually asked in PayPay OAs: adding binary strings)
- [ ] 8. String to Integer (atoi) — for practicing boundary conditions

### Weeks 3–5: New Core Areas

**Linked List**
- [ ] 206. Reverse Linked List
- [ ] 21. Merge Two Sorted Lists
- [ ] 141. Linked List Cycle
- [ ] 143. Reorder List
- [ ] 19. Remove Nth Node From End
- [ ] 146. LRU Cache (a backend interview staple)

**Trees**
- [ ] 226. Invert Binary Tree
- [ ] 104. Maximum Depth
- [ ] 543. Diameter of Binary Tree
- [ ] 102. Binary Tree Level Order Traversal
- [ ] 98. Validate Binary Search Tree
- [ ] 230. Kth Smallest in BST
- [ ] 105. Construct Tree from Preorder & Inorder
- [ ] 236. Lowest Common Ancestor

**Heap (asked in PayPay interviews + Mercari OAs)**
- [ ] 215. Kth Largest Element
- [ ] 973. K Closest Points to Origin
- [ ] 621. Task Scheduler

**Graphs (PayPay interviews / core for Rakuten / Mercari's Hard problems)**
- [ ] 200. Number of Islands
- [ ] 695. Max Area of Island
- [ ] 133. Clone Graph
- [ ] 994. Rotting Oranges
- [ ] 207. Course Schedule
- [ ] 210. Course Schedule II

**Intervals**
- [ ] 56. Merge Intervals
- [ ] 57. Insert Interval
- [ ] 435. Non-overlapping Intervals

### Weeks 6–7: Backtracking / Greedy / DP

**Backtracking**
- [ ] 78. Subsets
- [ ] 46. Permutations
- [ ] 39. Combination Sum
- [ ] ⭐ 22. Generate Parentheses (actually asked in Rakuten interviews)
- [ ] 79. Word Search

**Greedy**
- [ ] ⭐ 55. Jump Game (actually asked in Rakuten interviews)
- [ ] 45. Jump Game II
- [ ] 53. Maximum Subarray

**DP (the standard fundamentals)**
- [ ] 70. Climbing Stairs
- [ ] 198. House Robber
- [ ] 322. Coin Change
- [ ] 300. Longest Increasing Subsequence
- [ ] 62. Unique Paths
- [ ] 1143. Longest Common Subsequence

**Knapsack DP (asked in Mercari's senior OA)**
- [ ] 416. Partition Equal Subset Sum
- [ ] 494. Target Sum
- [ ] 1049. Last Stone Weight II

**Bit Manipulation (asked in Mercari OAs)**
- [ ] 136. Single Number
- [ ] 191. Number of 1 Bits
- [ ] 338. Counting Bits
- [ ] 268. Missing Number
- [ ] 371. Sum of Two Integers

### Weeks 8–10: Mock Tests + Expansion

**More Topological Sort (Mercari's Hard area — after 207/210)**
- [ ] 802. Find Eventual Safe States
- [ ] 310. Minimum Height Trees

**Implementation / Simulation (the "careful implementation" type on Japanese companies' in-house test platforms)**
- [ ] 54. Spiral Matrix
- [ ] 48. Rotate Image
- [ ] 71. Simplify Path
- [ ] 380. Insert Delete GetRandom O(1)
- [ ] 146. LRU Cache (review again — the baseline for design-style implementation)

**Upper Medium to Lower Hard (only if aiming for Amazon / Google Japan too)**
- [ ] 23. Merge k Sorted Lists
- [ ] 76. Minimum Window Substring
- [ ] 42. Trapping Rain Water
- [ ] 84. Largest Rectangle in Histogram

**Mock Test Routine**
- Weekend A: 70-minute timer + a set of 2 Easy & 2 Medium (PayPay OA simulation)
- Weekend B: 60-minute timer + a set of 3 Medium, aiming to get all fully correct (Mercari OA simulation)
- Join the LeetCode Weekly Contest (Sunday morning JST)
- Do a second pass only on problems that took over 30 minutes or that you got wrong
- From week 8, explain your solution process out loud in English (prep for live coding)
- System design once a week (PayPay: payment system + idempotency/concurrency / Rakuten: URL shortener, notification system, etc.)

---

## 3. Essential Java Snippets (Save Time in OAs)

- PriorityQueue + Comparator: `new PriorityQueue<>((a,b) -> b - a)`
- Deque as a stack/queue: `ArrayDeque<Integer> dq = new ArrayDeque<>()`
- Sorting + lambda: `Arrays.sort(arr, (a,b) -> a[0] - b[0])`
- StringBuilder: `sb.append() / sb.reverse() / sb.deleteCharAt()`
- HashMap frequency: `map.merge(key, 1, Integer::sum)`
- Bits: `n & (n-1)` (clears the lowest set bit), `n & 1` (odd/even), `Integer.bitCount(n)`

## 4. Edge Case Checklist (Emphasized in PayPay Reviews)

- Empty array / single element / all identical values
- int overflow → long
- Negative input
- Floating-point comparison → BigDecimal or convert to integers (cents)
- Binary/string numbers → strip leading zeros

## 5. Code Quality Habits (Mercari Evaluates This Even in OAs)

- Use production-level variable names (no a, b, tmp → left, right, freqMap)
- Split methods: if the main logic exceeds 30 lines, extract helpers
- Give magic numbers named constants

## 6. Application Strategy (Difficulty Ladder)

1. PayPay / Rakuten first — partial credit allowed, mostly Easy–Medium
2. Mercari next — requires a perfect score + code quality; take it on after building real test experience
3. LY (formerly LINE) uses its own test platform — recheck the latest format when you apply
