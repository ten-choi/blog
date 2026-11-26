# Ten Dev Notes

**Blog: [ten-dev-notes.blogspot.com](https://ten-dev-notes.blogspot.com/)**

Notes from a backend developer on the way to becoming a product engineer: system design, databases, caching, AI-assisted development, and what I learn along the way.

- [About](https://ten-dev-notes.blogspot.com/p/about.html) · [Contact](https://ten-dev-notes.blogspot.com/p/contact.html) · [Blog History](https://ten-dev-notes.blogspot.com/p/blog-history.html)
- Newer posts only (archive hidden): [ten-dev-notes.blogspot.com/?posts=current](https://ten-dev-notes.blogspot.com/?posts=current)

## How this blog works

Every post lives in this repository as a Markdown file, and a small script publishes it to Google Blogger through the Blogger API. The writing stays versioned and portable; Blogger is only where it is displayed.

```
content/dev/<year-half>/   Markdown posts (front matter holds title, labels, date, bloggerPostId)
content/dev/queue/         Posts waiting for the scheduled auto-publish workflow
content/pages/             Source of the About / Contact / Blog History pages
content/theme/             Blogger theme (dark mode, menus, sidebar widgets)
platforms/blogger/         Publishing scripts (Blogger API)
tools/                     Helpers: theme preview, README index, import and migration scripts
```

```bash
npm run publish:blogger -- "content/dev/2026-H2/<post>.md"   # create or update one post
node tools/theme-preview.js                                   # preview the theme at http://localhost:4000
node tools/update-readme.js                                   # refresh the post index below
```

## All posts

<!-- posts:start -->
_389 posts in total: 88 current, 301 in the archive. Last updated 2026-11-26._

## Posts (88)

### 2026

- [Redis Deep Dive: Why It Is Fast on One Thread, and How to Use It Well](https://ten-dev-notes.blogspot.com/2026/11/redis-deep-dive-why-it-is-fast-on-one.html) <sub>2026-11-26</sub>
- [Making a Web Service Fast: Cache Layers, HTTP Caching, and Cache vs Message Queue](https://ten-dev-notes.blogspot.com/2026/11/making-web-service-fast-cache-layers.html) <sub>2026-11-25</sub>
- [Fukuoka's Next Chapter — My Takeaways from Kyushu Roundtable #7](https://ten-dev-notes.blogspot.com/2026/10/fukuokas-next-chapter-my-takeaways-from.html) <sub>2026-10-30</sub>
- [What You Actually Gain from AI Agent Tools](https://ten-dev-notes.blogspot.com/2026/09/what-you-actually-gain-from-ai-agent.html) <sub>2026-09-28</sub>
- [Three Ways to Cut Token Usage in AI Coding - Headroom, Graphify, Ponytail](https://ten-dev-notes.blogspot.com/2026/09/three-ways-to-cut-token-usage-in-ai.html) <sub>2026-09-28</sub>
- [DBMS Made Ridiculously Easy - Controlling Execution Plans with Optimizer Hints](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-controlling.html) <sub>2026-09-14</sub>
- [DBMS Made Ridiculously Easy - Optimizer Statistics and How Cost Is Calculated](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-optimizer.html) <sub>2026-09-14</sub>
- [DBMS Made Ridiculously Easy - Locks and Transaction Concurrency Control](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-locks-and.html) <sub>2026-09-13</sub>
- [DBMS Made Ridiculously Easy - Partition-Based DML Tuning: Managing Huge Tables](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-partition.html) <sub>2026-09-13</sub>
- [DBMS Made Ridiculously Easy - Direct Path I/O: Optimizing Bulk Data Loads](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-direct-path.html) <sub>2026-09-12</sub>
- [DBMS Made Ridiculously Easy - Basic DML Tuning: How Insert, Update, Delete Really Work](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-basic-dml.html) <sub>2026-09-12</sub>
- [DBMS Made Ridiculously Easy - Skipping Sorts with Indexes](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-skipping.html) <sub>2026-09-11</sub>
- [DBMS Made Ridiculously Easy - Writing SQL That Avoids Sorts](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-writing-sql.html) <sub>2026-09-11</sub>
- [DBMS Made Ridiculously Easy - How Sorting Works and Memory vs Disk Sorts](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-how-sorting.html) <sub>2026-09-10</sub>
- [DBMS Made Ridiculously Easy - Subquery Joins and Unnesting](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-subquery.html) <sub>2026-09-10</sub>
- [DBMS Made Ridiculously Easy - Hash Join, the Answer for Large Data Sets](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-hash-join.html) <sub>2026-09-07</sub>
- [DBMS Made Ridiculously Easy - How the Sort Merge Join Works](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-how-sort.html) <sub>2026-09-07</sub>
- [DBMS Made Ridiculously Easy - How the Nested Loops Join Works](https://ten-dev-notes.blogspot.com/2026/09/dbms-made-ridiculously-easy-how-nested.html) <sub>2026-09-07</sub>
- [LeetCode 121. Best Time to Buy and Sell Stock - One-Pass O(n) Solution Explained](https://ten-dev-notes.blogspot.com/2026/08/leetcode-121-best-time-to-buy-and-sell.html) <sub>2026-08-28</sub>
- [DBMS Made Ridiculously Easy - Index Scan Efficiency and Index Design](https://ten-dev-notes.blogspot.com/2026/07/dbms-made-ridiculously-easy-index-scan.html) <sub>2026-07-30</sub>
- [DBMS Made Ridiculously Easy - Minimizing Table Access and Partial Range Processing](https://ten-dev-notes.blogspot.com/2026/07/dbms-made-ridiculously-easy-minimizing.html) <sub>2026-07-30</sub>
- [Taking the JLPT N2: My Late-2019 Test Day Experience](https://ten-dev-notes.blogspot.com/2026/07/taking-jlpt-n2-my-late-2019-test-day.html) <sub>2026-07-27</sub>
- [Effective Troubleshooting - A Comprehensive Guide](https://ten-dev-notes.blogspot.com/2026/06/effective-troubleshooting-comprehensive.html) <sub>2026-06-22</sub>
- [How to Estimate a Project Schedule - A Logical Approach](https://ten-dev-notes.blogspot.com/2026/06/how-to-estimate-project-schedule.html) <sub>2026-06-19</sub>
- [DBMS Made Ridiculously Easy - Index Scan Types and Extended Features](https://ten-dev-notes.blogspot.com/2026/06/dbms-made-ridiculously-easy-index-scan.html) <sub>2026-06-19</sub>
- [DBMS Made Ridiculously Easy - Index Basics and What Breaks a Range Scan](https://ten-dev-notes.blogspot.com/2026/06/dbms-made-ridiculously-easy-index.html) <sub>2026-06-18</sub>
- [DBMS Made Ridiculously Easy - B-Tree Index Structure and How Search Works](https://ten-dev-notes.blogspot.com/2026/06/dbms-made-ridiculously-easy-b-tree.html) <sub>2026-06-18</sub>
- [DBMS Made Ridiculously Easy - I/O Principles: Block-Based I/O and Logical vs Physical I/O](https://ten-dev-notes.blogspot.com/2026/06/dbms-made-ridiculously-easy-io.html) <sub>2026-06-17</sub>
- [DBMS Made Ridiculously Easy - The Execution Engine: SQL's Final Journey](https://ten-dev-notes.blogspot.com/2026/06/dbms-made-ridiculously-easy-execution.html) <sub>2026-06-17</sub>
- [Using AI Well (Part 4) — How to Trust What Comes Back: Verification and Trust](https://ten-dev-notes.blogspot.com/2026/06/using-ai-well-part-4-how-to-trust-what.html) <sub>2026-06-16</sub>
- [Using AI Well (Part 3) — Save Tokens and Instruct Properly](https://ten-dev-notes.blogspot.com/2026/06/using-ai-well-part-3-save-tokens-and.html) <sub>2026-06-16</sub>
- [Using AI Well (Part 2) — How to Use It Well: Seven Maturity Stages](https://ten-dev-notes.blogspot.com/2026/06/using-ai-well-part-2-how-to-use-it-well.html) <sub>2026-06-15</sub>
- [Using AI Well (Part 1) — What You Can Use: A Developer's Map of AI Features](https://ten-dev-notes.blogspot.com/2026/06/using-ai-well-part-1-what-you-can-use.html) <sub>2026-06-15</sub>
- [Claude Fable 5 Suspended: Why Anthropic Pulled Its Best Model 3 Days After Launch](https://ten-dev-notes.blogspot.com/2026/06/claude-fable-5-suspended-why-anthropic.html) <sub>2026-06-15</sub>
- [DBMS Made Ridiculously Easy - How the Optimizer Builds the Best Execution Plan](https://ten-dev-notes.blogspot.com/2026/05/dbms-made-ridiculously-easy-how.html) <sub>2026-05-29</sub>
- [GitFlow Workflow - A Practical Branching Strategy Guide](https://ten-dev-notes.blogspot.com/2026/05/gitflow-workflow-practical-branching.html) <sub>2026-05-28</sub>
- [Agile Scrum - The Easy Guide to Self-Learning](https://ten-dev-notes.blogspot.com/2026/05/agile-scrum-easy-guide-to-self-learning.html) <sub>2026-05-26</sub>
- [Rising Productivity, Vanishing Jobs: A Developer's Take on the AI Era](https://ten-dev-notes.blogspot.com/2026/05/rising-productivity-vanishing-jobs.html) <sub>2026-05-20</sub>
- [Why Writing Still Matters — A Developer's Case for Thinking Out Loud11](https://ten-dev-notes.blogspot.com/2026/05/why-writing-still-matters-developers.html) <sub>2026-05-20</sub>
- [DBMS Made Ridiculously Easy - SQL Parsing and the Plan Cache](https://ten-dev-notes.blogspot.com/2026/05/dbms-made-ridiculously-easy-sql-parsing.html) <sub>2026-05-18</sub>
- [Mermaid vs Archify - Choosing the Right Tool for Architecture Diagrams](https://ten-dev-notes.blogspot.com/2026/05/mermaid-vs-archify-choosing-right-tool.html) <sub>2026-05-15</sub>
- [System Design Mock Interview - LLD: "Implement an LRU Cache and a Token Bucket"](https://ten-dev-notes.blogspot.com/2026/04/system-design-mock-interview-lld.html) <sub>2026-04-29</sub>
- [System Design Mock Interview - HLD: "Design a URL Shortener — and a Rate Limiter, Too"](https://ten-dev-notes.blogspot.com/2026/04/system-design-mock-interview-hld-design.html) <sub>2026-04-17</sub>
- [System Design Mock Interview - LLD: "Design That Seat Hold as Classes"](https://ten-dev-notes.blogspot.com/2026/04/system-design-mock-interview-lld-design.html) <sub>2026-04-08</sub>
- [System Design Mock Interview - HLD: "Design a Concert Ticket Booking System"](https://ten-dev-notes.blogspot.com/2026/03/system-design-mock-interview-hld-design_01867244238.html) <sub>2026-03-27</sub>
- [System Design Mock Interview - LLD: "Design That Wallet (the Ledger) as Classes"](https://ten-dev-notes.blogspot.com/2026/03/system-design-mock-interview-lld-design.html) <sub>2026-03-17</sub>
- [System Design Mock Interview - HLD: "Design a Mobile Payment Service like PayPay"](https://ten-dev-notes.blogspot.com/2026/03/system-design-mock-interview-hld-design.html) <sub>2026-03-05</sub>
- [System Design Mock Interview - LLD: "Design That Message Delivery as Classes"](https://ten-dev-notes.blogspot.com/2026/02/system-design-mock-interview-lld-design.html) <sub>2026-02-23</sub>
- [System Design Mock Interview - HLD: "Design a Messenger Like LINE"](https://ten-dev-notes.blogspot.com/2026/02/system-design-mock-interview-hld-design.html) <sub>2026-02-15</sub>
- [System Design Mock Interview - LLD: "Now Design That Feed Service as Classes"](https://ten-dev-notes.blogspot.com/2026/02/system-design-mock-interview-lld-now.html) <sub>2026-02-06</sub>
- [System Design Mock Interview - HLD: "Design Instagram"](https://ten-dev-notes.blogspot.com/2026/01/system-design-mock-interview-hld-design_0511131778.html) <sub>2026-01-27</sub>
- [System Design Mock Interview - LLD: "Design That Dispatch Service as Classes"](https://ten-dev-notes.blogspot.com/2026/01/system-design-mock-interview-lld-design.html) <sub>2026-01-14</sub>
- [System Design Mock Interview - HLD: "Design a Food Delivery App (Uber Eats)"](https://ten-dev-notes.blogspot.com/2026/01/system-design-mock-interview-hld-design.html) <sub>2026-01-03</sub>

### 2025

- [1318. Minimum Flips to Make a OR b Equal to c](https://ten-dev-notes.blogspot.com/2025/09/1318-minimum-flips-to-make-or-b-equal.html) <sub>2025-09-28</sub>
- [2215. Find the Difference of Two Arrays](https://ten-dev-notes.blogspot.com/2025/09/2215-find-difference-of-two-arrays.html) <sub>2025-09-17</sub>
- [1926. Nearest Exit from Entrance in Maze](https://ten-dev-notes.blogspot.com/2025/09/1926-nearest-exit-from-entrance-in-maze.html) <sub>2025-09-12</sub>
- [933. Number of Recent Calls](https://ten-dev-notes.blogspot.com/2025/08/933-number-of-recent-calls.html) <sub>2025-08-26</sub>
- [901. Online Stock Span](https://ten-dev-notes.blogspot.com/2025/08/901-online-stock-span.html) <sub>2025-08-21</sub>
- [872. Leaf-Similar Trees](https://ten-dev-notes.blogspot.com/2025/08/872-leaf-similar-trees.html) <sub>2025-08-14</sub>
- [841. Keys and Rooms](https://ten-dev-notes.blogspot.com/2025/08/841-keys-and-rooms.html) <sub>2025-08-11</sub>
- [746. Min Cost Climbing Stairs](https://ten-dev-notes.blogspot.com/2025/08/746-min-cost-climbing-stairs.html) <sub>2025-08-02</sub>
- [547. Number of Provinces](https://ten-dev-notes.blogspot.com/2025/07/547-number-of-provinces.html) <sub>2025-07-19</sub>
- [392. Is Subsequence](https://ten-dev-notes.blogspot.com/2025/07/392-is-subsequence.html) <sub>2025-07-12</sub>
- [283. Move Zeroes](https://ten-dev-notes.blogspot.com/2025/06/283-move-zeroes.html) <sub>2025-07-01</sub>
- [242. Valid Anagram](https://ten-dev-notes.blogspot.com/2025/06/242-valid-anagram.html) <sub>2025-06-25</sub>
- [217. Contains Duplicate](https://ten-dev-notes.blogspot.com/2025/06/217-contains-duplicate.html) <sub>2025-06-19</sub>
- [198. House Robber](https://ten-dev-notes.blogspot.com/2025/06/198-house-robber.html) <sub>2025-06-08</sub>
- [153. Find Minimum in Rotated Sorted Array](https://ten-dev-notes.blogspot.com/2025/05/153-find-minimum-in-rotated-sorted-array.html) <sub>2025-06-01</sub>
- [49. Group Anagrams](https://ten-dev-notes.blogspot.com/2025/05/49-group-anagrams.html) <sub>2025-05-15</sub>
- [15. 3Sum](https://ten-dev-notes.blogspot.com/2025/05/15-3sum.html) <sub>2025-05-08</sub>
- [1. Two Sum](https://ten-dev-notes.blogspot.com/2025/05/1-two-sum.html) <sub>2025-05-05</sub>
- [Jenkinsを利用したTomcat & Java JAR Docker CI/CD構築ガイド](https://ten-dev-notes.blogspot.com/2025/03/jenkinstomcat-java-jar-docker-cicd.html) <sub>2025-03-12</sub>
- [CI/CD with Jenkins, Docker & Git - A Simple Guide for Junior Developers](https://ten-dev-notes.blogspot.com/2025/03/cicd-with-jenkins-docker-git-simple.html) <sub>2025-03-08</sub>

### 2024

- [MySQL Performance Optimization](https://ten-dev-notes.blogspot.com/2024/12/mysql-performance-optimization.html) <sub>2024-12-21</sub>
- [\[ Docs \] チームのための正しい文書化方法](https://ten-dev-notes.blogspot.com/2024/02/docs.html) <sub>2024-03-01</sub>
- [\[ Eng \] Go to the Pharmacy in English with vanessa](https://ten-dev-notes.blogspot.com/2024/02/eng-go-to-pharmacy-in-english-with.html) <sub>2024-02-29</sub>

### 2023

- [\[ Spring \] aopを適用して例外処理をしましょう](https://ten-dev-notes.blogspot.com/2023/12/spring-aop.html) <sub>2023-12-11</sub>
- [\[ Spring \] java springを簡単に始めましょう](https://ten-dev-notes.blogspot.com/2023/12/spring-java-spring.html) <sub>2023-12-07</sub>
- [\[ Pattern \] database per service pattern](https://ten-dev-notes.blogspot.com/2023/12/pattern-database-per-service-pattern.html) <sub>2023-12-07</sub>
- [\[ Spring \] Springに対して](https://ten-dev-notes.blogspot.com/2023/11/spring-spring.html) <sub>2023-12-01</sub>
- [\[ Ide \] intellijで整列する方法](https://ten-dev-notes.blogspot.com/2023/11/ide-intellij.html) <sub>2023-11-26</sub>

### 2021

- [The direction of English category has been determined](https://ten-dev-notes.blogspot.com/2021/12/the-direction-of-english-category-has.html) <sub>2021-12-30</sub>
- [June twenty-nine, twenty twenty-one](https://ten-dev-notes.blogspot.com/2021/10/june-twenty-nine-twenty-twenty-one.html) <sub>2021-10-18</sub>
- [the diary when I was start to English](https://ten-dev-notes.blogspot.com/2021/06/the-diary-when-i-was-start-to-english.html) <sub>2021-06-29</sub>
- [June twenty-seven, twenty twenty-one](https://ten-dev-notes.blogspot.com/2021/06/june-twenty-seven-twenty-twenty-one.html) <sub>2021-06-29</sub>
- [how to make friends in south korea (I'm korean)](https://ten-dev-notes.blogspot.com/2021/02/how-to-make-friends-in-south-korea-im.html) <sub>2021-02-06</sub>

### 2020

- [やはり憂慮していたことが起こりました。](https://ten-dev-notes.blogspot.com/2020/10/blog-post.html) <sub>2020-10-07</sub>
- [韓国でITやっています。](https://ten-dev-notes.blogspot.com/2020/09/it.html) <sub>2020-09-10</sub>

## Archive (301)

Earlier notes, originally written in Korean (2020 onward) and translated into English. Kept as a record of how I got here.

<details>
<summary><b>2025</b> (61)</summary>

- [Business Intelligence — Turning Data Into Decisions](https://ten-dev-notes.blogspot.com/2025/12/business-intelligence-turning-data-into.html) <sub>2025-12-25</sub>
- [Data Governance Made Simple (Part 3) — Quality, Security, and Compliance](https://ten-dev-notes.blogspot.com/2025/12/data-governance-made-simple-part-3.html) <sub>2025-12-19</sub>
- [Data Governance Made Simple (Part 2) — Metadata, the Data Catalog, and Lineage](https://ten-dev-notes.blogspot.com/2025/12/data-governance-made-simple-part-2.html) <sub>2025-12-13</sub>
- [Data Governance Made Simple (Part 1) — What It Is and Why Every Team Eventually Needs It](https://ten-dev-notes.blogspot.com/2025/12/data-governance-made-simple-part-1-what.html) <sub>2025-12-07</sub>
- [Moving Data (Part 5) — Batch vs. Streaming: How Fresh Does Data Need to Be?](https://ten-dev-notes.blogspot.com/2025/12/moving-data-part-5-batch-vs-streaming.html) <sub>2025-12-02</sub>
- [Moving Data (Part 4) — Data Integration: Making Many Sources Agree](https://ten-dev-notes.blogspot.com/2025/11/moving-data-part-4-data-integration.html) <sub>2025-11-24</sub>
- [Moving Data (Part 3) — ETL vs. ELT: Where Should You Transform?](https://ten-dev-notes.blogspot.com/2025/11/moving-data-part-3-etl-vs-elt-where.html) <sub>2025-11-20</sub>
- [Moving Data (Part 2) — Data Ingestion: Getting Data In](https://ten-dev-notes.blogspot.com/2025/11/moving-data-part-2-data-ingestion.html) <sub>2025-11-13</sub>
- [Moving Data (Part 1) — What a Data Pipeline Actually Is](https://ten-dev-notes.blogspot.com/2025/11/moving-data-part-1-what-data-pipeline.html) <sub>2025-11-07</sub>
- [Understanding the Data Lake (Part 3) — The Lakehouse and Open Table Formats](https://ten-dev-notes.blogspot.com/2025/10/understanding-data-lake-part-3.html) <sub>2025-11-01</sub>
- [Understanding the Data Lake (Part 2) — Zones, Storage, and File Formats](https://ten-dev-notes.blogspot.com/2025/10/understanding-data-lake-part-2-zones.html) <sub>2025-10-25</sub>
- [Understanding the Data Lake (Part 1) — Lake vs. Warehouse, and Why Both Exist](https://ten-dev-notes.blogspot.com/2025/10/understanding-data-lake-part-1-lake-vs.html) <sub>2025-10-20</sub>
- [The Data Warehouse (Part 2) — Star Schemas, Slowly Changing Dimensions, and Data Marts](https://ten-dev-notes.blogspot.com/2025/10/the-data-warehouse-part-2-star-schemas.html) <sub>2025-10-14</sub>
- [The Data Warehouse (Part 1) — OLTP vs. OLAP and the Modeling Foundations](https://ten-dev-notes.blogspot.com/2025/10/the-data-warehouse-part-1-oltp-vs-olap.html) <sub>2025-10-07</sub>
- [The Modern Data Platform — A Map of How the Pieces Fit Together](https://ten-dev-notes.blogspot.com/2025/10/the-modern-data-platform-map-of-how.html) <sub>2025-10-02</sub>
- [2352. Equal Row and Column Pairs](https://ten-dev-notes.blogspot.com/2025/09/2352-equal-row-and-column-pairs.html) <sub>2025-09-24</sub>
- [2300. Successful Pairs of Spells and Potions](https://ten-dev-notes.blogspot.com/2025/09/2300-successful-pairs-of-spells-and.html) <sub>2025-09-21</sub>
- [1657. Determine if Two Strings Are Close](https://ten-dev-notes.blogspot.com/2025/09/1657-determine-if-two-strings-are-close.html) <sub>2025-09-10</sub>
- [1207. Unique Number of Occurrences](https://ten-dev-notes.blogspot.com/2025/09/1207-unique-number-of-occurrences.html) <sub>2025-09-05</sub>
- [1143. Longest Common Subsequence](https://ten-dev-notes.blogspot.com/2025/09/1143-longest-common-subsequence.html) <sub>2025-09-02</sub>
- [1137. N-th Tribonacci Number](https://ten-dev-notes.blogspot.com/2025/08/1137-n-th-tribonacci-number.html) <sub>2025-08-29</sub>
- [875. Koko Eating Bananas](https://ten-dev-notes.blogspot.com/2025/08/875-koko-eating-bananas.html) <sub>2025-08-18</sub>
- [790. Domino and Tromino Tiling](https://ten-dev-notes.blogspot.com/2025/08/790-domino-and-tromino-tiling.html) <sub>2025-08-07</sub>
- [739. Daily Temperatures](https://ten-dev-notes.blogspot.com/2025/07/739-daily-temperatures.html) <sub>2025-07-31</sub>
- [Understanding the Monotonic Stack Clearly](https://ten-dev-notes.blogspot.com/2025/07/monotonic-stack.html) <sub>2025-07-28</sub>
- [714. Best Time to Buy and Sell Stock with Transaction Fee](https://ten-dev-notes.blogspot.com/2025/07/714-best-time-to-buy-and-sell-stock.html) <sub>2025-07-26</sub>
- [LeetCode 560. Subarray Sum Equals K - Prefix Sum + HashMap in O(n)](https://ten-dev-notes.blogspot.com/2025/07/leetcode-560-subarray-sum-equals-k.html) <sub>2025-07-23</sub>
- [424. Longest Repeating Character Replacement](https://ten-dev-notes.blogspot.com/2025/07/424-longest-repeating-character.html) <sub>2025-07-16</sub>
- [374. Guess Number Higher or Lower](https://ten-dev-notes.blogspot.com/2025/07/374-guess-number-higher-or-lower.html) <sub>2025-07-07</sub>
- [347. Top K Frequent Elements](https://ten-dev-notes.blogspot.com/2025/07/347-top-k-frequent-elements.html) <sub>2025-07-04</sub>
- [238. Product of Array Except Self](https://ten-dev-notes.blogspot.com/2025/06/238-product-of-array-except-self.html) <sub>2025-06-23</sub>
- [206. Reverse Linked List](https://ten-dev-notes.blogspot.com/2025/06/206-reverse-linked-list.html) <sub>2025-06-14</sub>
- [200. Number of Islands](https://ten-dev-notes.blogspot.com/2025/06/200-number-of-islands.html) <sub>2025-06-12</sub>
- [162. Find Peak Element](https://ten-dev-notes.blogspot.com/2025/06/162-find-peak-element.html) <sub>2025-06-04</sub>
- [My English Learning Journey](https://ten-dev-notes.blogspot.com/2025/05/my-english-learning-journey.html) <sub>2025-05-30</sub>
- [104. Maximum Depth of Binary Tree](https://ten-dev-notes.blogspot.com/2025/05/104-maximum-depth-of-binary-tree.html) <sub>2025-05-27</sub>
- [72. Edit Distance](https://ten-dev-notes.blogspot.com/2025/05/72.html) <sub>2025-05-23</sub>
- [LeetCode 62: Unique Paths - A DP Approach](https://ten-dev-notes.blogspot.com/2025/05/leetcode-62-unique-paths-dp.html) <sub>2025-05-20</sub>
- [17. Letter Combinations of a Phone Number](https://ten-dev-notes.blogspot.com/2025/05/17-letter-combinations-of-phone-number.html) <sub>2025-05-13</sub>
- [10-Week Coding Test Plan for Backend Roles at English-Speaking Tech Companies in Tokyo (Java)](https://ten-dev-notes.blogspot.com/2025/04/it-10-java.html) <sub>2025-05-01</sub>
- [What Developers Should Do in the Age of AI](https://ten-dev-notes.blogspot.com/2025/04/ai.html) <sub>2025-04-29</sub>
- [Top 10 Core Principles of Team Leadership](https://ten-dev-notes.blogspot.com/2025/04/top-10.html) <sub>2025-04-18</sub>
- [I Built a Chrome Extension for A-B Repeat on Audible](https://ten-dev-notes.blogspot.com/2025/04/blog-post_12.html) <sub>2025-04-12</sub>
- [I Built a Chrome Extension for Memorizing English Vocabulary](https://ten-dev-notes.blogspot.com/2025/04/blog-post.html) <sub>2025-04-07</sub>
- [Interviewing for IT Positions at English-First Companies in Japan](https://ten-dev-notes.blogspot.com/2025/04/it.html) <sub>2025-04-03</sub>
- [Kubernetes Installation and Setup Guide](https://ten-dev-notes.blogspot.com/2025/03/kubernetes.html) <sub>2025-03-28</sub>
- [Using ECS](https://ten-dev-notes.blogspot.com/2025/03/ecs.html) <sub>2025-03-23</sub>
- [Building a Docker CI/CD Pipeline for Tomcat & Java JARs with Jenkins](https://ten-dev-notes.blogspot.com/2025/03/jenkins-tomcat-java-jar-docker-cicd.html) <sub>2025-03-17</sub>
- [My Blog's History](https://ten-dev-notes.blogspot.com/2025/03/blog-post.html) <sub>2025-03-02</sub>
- [Supply Chain Security - A Guide to Dependency Security](https://ten-dev-notes.blogspot.com/2025/02/supply-chain-security.html) <sub>2025-02-27</sub>
- [SSDLC - A Guide to the Secure Software Development Lifecycle](https://ten-dev-notes.blogspot.com/2025/02/ssdlc.html) <sub>2025-02-21</sub>
- [Secrets & Key Management - Keeping Sensitive Data Safe](https://ten-dev-notes.blogspot.com/2025/02/secrets-key-management.html) <sub>2025-02-16</sub>
- [Network Security - Key Concepts You Should Know](https://ten-dev-notes.blogspot.com/2025/02/blog-post_10.html) <sub>2025-02-11</sub>
- [Logging & Monitoring - A Guide to Tracking Security Events](https://ten-dev-notes.blogspot.com/2025/02/logging-monitoring.html) <sub>2025-02-08</sub>
- [Infrastructure Security - Key Concepts You Should Know](https://ten-dev-notes.blogspot.com/2025/02/blog-post.html) <sub>2025-02-03</sub>
- [Frontend Security - Core Concepts You Need to Know](https://ten-dev-notes.blogspot.com/2025/01/frontend.html) <sub>2025-01-30</sub>
- [Database Security - Core Concepts You Need to Know](https://ten-dev-notes.blogspot.com/2025/01/blog-post_25.html) <sub>2025-01-25</sub>
- [Compliance & Privacy - A Guide to GDPR and CCPA Compliance](https://ten-dev-notes.blogspot.com/2025/01/compliance-privacy-gdpr-ccpa.html) <sub>2025-01-20</sub>
- [Authentication & Authorization - The Complete Guide](https://ten-dev-notes.blogspot.com/2025/01/authentication-authorization.html) <sub>2025-01-15</sub>
- [Application Security - Core Concepts You Need to Know](https://ten-dev-notes.blogspot.com/2025/01/blog-post.html) <sub>2025-01-10</sub>
- [API Security - 12 Core Concepts You Need to Know](https://ten-dev-notes.blogspot.com/2025/01/api-12.html) <sub>2025-01-06</sub>

</details>

<details>
<summary><b>2024</b> (62)</summary>

- [Snowflake vs Databricks: Comparing Cloud Data Platforms](https://ten-dev-notes.blogspot.com/2024/12/snowflake-databricks.html) <sub>2024-12-25</sub>
- [Getting Started with ClickHouse - OLTP vs OLAP, What's Actually Different](https://ten-dev-notes.blogspot.com/2024/12/clickhouse-oltp-vs-olap.html) <sub>2024-12-08</sub>
- [MySQL Performance Optimization - Hands-on Test with 12 Million Rows](https://ten-dev-notes.blogspot.com/2024/10/mysql-performance-optimization-hands-on.html) <sub>2024-10-01</sub>
- [8.9 Operational Security: Firewalls and Intrusion Detection Systems](https://ten-dev-notes.blogspot.com/2024/09/89.html) <sub>2024-09-25</sub>
- [8.8 Securing Wireless LANs and 4G/5G Cellular Networks](https://ten-dev-notes.blogspot.com/2024/09/88-4g-5g.html) <sub>2024-09-22</sub>
- [8.7 Network-Layer Security: IPsec and Virtual Private Networks](https://ten-dev-notes.blogspot.com/2024/09/87-ipsec.html) <sub>2024-09-18</sub>
- [8.6 Securing TCP Connections: TLS](https://ten-dev-notes.blogspot.com/2024/09/86-tcp-tls.html) <sub>2024-09-16</sub>
- [8.5 Securing E-Mail](https://ten-dev-notes.blogspot.com/2024/09/85.html) <sub>2024-09-10</sub>
- [8.4 End-Point Authentication](https://ten-dev-notes.blogspot.com/2024/09/84.html) <sub>2024-09-07</sub>
- [8.3 Message Integrity and Digital Signatures](https://ten-dev-notes.blogspot.com/2024/09/83.html) <sub>2024-09-04</sub>
- [8.2 Principles of Cryptography](https://ten-dev-notes.blogspot.com/2024/09/82.html) <sub>2024-09-01</sub>
- [8.1 What Is Network Security?](https://ten-dev-notes.blogspot.com/2024/08/81.html) <sub>2024-08-28</sub>
- [7.7 Wireless and Mobility: Impact on Higher-Layer Protocols](https://ten-dev-notes.blogspot.com/2024/08/77.html) <sub>2024-08-25</sub>
- [7.6 Mobility Management in Practice](https://ten-dev-notes.blogspot.com/2024/08/76.html) <sub>2024-08-19</sub>
- [7.5 Mobility Management: Principles](https://ten-dev-notes.blogspot.com/2024/08/75.html) <sub>2024-08-16</sub>
- [7.4 Cellular Networks: 4G and 5G](https://ten-dev-notes.blogspot.com/2024/08/74-4g-5g.html) <sub>2024-08-13</sub>
- [7.3 Wi-Fi: 802.11 Wireless LANs](https://ten-dev-notes.blogspot.com/2024/08/73-80211.html) <sub>2024-08-10</sub>
- [7.2 Wireless Links and Network Characteristics](https://ten-dev-notes.blogspot.com/2024/08/72.html) <sub>2024-08-05</sub>
- [7.1 Introduction](https://ten-dev-notes.blogspot.com/2024/08/71.html) <sub>2024-08-01</sub>
- [6.7 Retrospective: A Day in the Life of a Web Page Request](https://ten-dev-notes.blogspot.com/2024/07/67.html) <sub>2024-07-29</sub>
- [6.6 Data Center Networking](https://ten-dev-notes.blogspot.com/2024/07/66.html) <sub>2024-07-26</sub>
- [6.5 Link Virtualization: A Network as a Link Layer](https://ten-dev-notes.blogspot.com/2024/07/65.html) <sub>2024-07-21</sub>
- [6.4 Switched Local Area Networks](https://ten-dev-notes.blogspot.com/2024/07/64.html) <sub>2024-07-19</sub>
- [6.3 Multiple Access Links and Protocols](https://ten-dev-notes.blogspot.com/2024/07/63.html) <sub>2024-07-15</sub>
- [6.2 Error-Detection and Error-Correction Techniques](https://ten-dev-notes.blogspot.com/2024/07/62.html) <sub>2024-07-10</sub>
- [6.1 Introduction to the Link Layer](https://ten-dev-notes.blogspot.com/2024/07/61.html) <sub>2024-07-06</sub>
- [5.7 Network Management with SNMP, NETCONF, and YANG](https://ten-dev-notes.blogspot.com/2024/07/57-snmp-netconf-yang.html) <sub>2024-07-03</sub>
- [5.6 The Internet Control Message Protocol (ICMP)](https://ten-dev-notes.blogspot.com/2024/06/56-icmp.html) <sub>2024-06-30</sub>
- [5.5 The Software-Defined Networking (SDN) Control Plane](https://ten-dev-notes.blogspot.com/2024/06/55-sdn.html) <sub>2024-06-27</sub>
- [5.4 Routing Among Internet Service Providers (ISPs): BGP](https://ten-dev-notes.blogspot.com/2024/06/54-isp-bgp.html) <sub>2024-06-21</sub>
- [5.3 Intra-AS Routing in the Internet: OSPF](https://ten-dev-notes.blogspot.com/2024/06/53-as-ospf.html) <sub>2024-06-19</sub>
- [5.2 Routing Algorithms](https://ten-dev-notes.blogspot.com/2024/06/52.html) <sub>2024-06-15</sub>
- [5.1 Introduction](https://ten-dev-notes.blogspot.com/2024/06/51.html) <sub>2024-06-11</sub>
- [4.5 Middleboxes](https://ten-dev-notes.blogspot.com/2024/06/45.html) <sub>2024-06-07</sub>
- [4.4 Generalized Forwarding and Software-Defined Networking (SDN)](https://ten-dev-notes.blogspot.com/2024/06/44-sdn.html) <sub>2024-06-04</sub>
- [4.3 The Internet Protocol (IP): IPv4, Addressing, IPv6, and More](https://ten-dev-notes.blogspot.com/2024/05/43-ip-ipv4-ipv6.html) <sub>2024-05-31</sub>
- [4.2 What's Inside a Router?](https://ten-dev-notes.blogspot.com/2024/05/42.html) <sub>2024-05-27</sub>
- [4.1 Network Layer Overview](https://ten-dev-notes.blogspot.com/2024/05/41.html) <sub>2024-05-23</sub>
- [3.8 Evolution of Transport-Layer Functionality](https://ten-dev-notes.blogspot.com/2024/05/38.html) <sub>2024-05-20</sub>
- [3.7 TCP Congestion Control](https://ten-dev-notes.blogspot.com/2024/05/37-tcp.html) <sub>2024-05-16</sub>
- [3.6 Principles of Congestion Control](https://ten-dev-notes.blogspot.com/2024/05/36.html) <sub>2024-05-12</sub>
- [3.5 Connection-Oriented Transport: TCP](https://ten-dev-notes.blogspot.com/2024/05/35-tcp.html) <sub>2024-05-09</sub>
- [3.4 Principles of Reliable Data Transfer](https://ten-dev-notes.blogspot.com/2024/05/34.html) <sub>2024-05-04</sub>
- [3.3 Connectionless Transport: UDP](https://ten-dev-notes.blogspot.com/2024/04/33-udp.html) <sub>2024-04-30</sub>
- [3.2 Multiplexing and Demultiplexing](https://ten-dev-notes.blogspot.com/2024/04/32.html) <sub>2024-04-27</sub>
- [3.1 Introduction and Transport-Layer Services](https://ten-dev-notes.blogspot.com/2024/04/31.html) <sub>2024-04-23</sub>
- [2.7 Socket Programming: Creating Network Applications](https://ten-dev-notes.blogspot.com/2024/04/27.html) <sub>2024-04-21</sub>
- [2.6 Video Streaming and Content Distribution Networks](https://ten-dev-notes.blogspot.com/2024/04/26.html) <sub>2024-04-16</sub>
- [2.5 Peer-to-Peer File Distribution](https://ten-dev-notes.blogspot.com/2024/04/25-p2p.html) <sub>2024-04-13</sub>
- [2.4 DNS: The Internet's Directory Service](https://ten-dev-notes.blogspot.com/2024/04/24-dns.html) <sub>2024-04-09</sub>
- [2.3 Electronic Mail in the Internet](https://ten-dev-notes.blogspot.com/2024/04/23.html) <sub>2024-04-06</sub>
- [2.2 The Web and HTTP](https://ten-dev-notes.blogspot.com/2024/04/22-http.html) <sub>2024-04-01</sub>
- [2.1 Principles of Network Applications](https://ten-dev-notes.blogspot.com/2024/03/21.html) <sub>2024-03-29</sub>
- [1.7 History of Computer Networking and the Internet](https://ten-dev-notes.blogspot.com/2024/03/17.html) <sub>2024-03-25</sub>
- [1.6 Networks Under Attack](https://ten-dev-notes.blogspot.com/2024/03/16.html) <sub>2024-03-21</sub>
- [1.5 Protocol Layers and Their Service Models](https://ten-dev-notes.blogspot.com/2024/03/15.html) <sub>2024-03-19</sub>
- [\[ IntelliJ \] Fixing Garbled Korean Characters](https://ten-dev-notes.blogspot.com/2024/03/intellij.html) <sub>2024-03-18</sub>
- [1.4 Delay, Loss, and Throughput in Packet-Switched Networks](https://ten-dev-notes.blogspot.com/2024/03/14.html) <sub>2024-03-15</sub>
- [1.3 The Network Core](https://ten-dev-notes.blogspot.com/2024/03/13.html) <sub>2024-03-11</sub>
- [1.2 The Network Edge](https://ten-dev-notes.blogspot.com/2024/03/12.html) <sub>2024-03-06</sub>
- [1.1 What Is the Internet?](https://ten-dev-notes.blogspot.com/2024/03/11.html) <sub>2024-03-04</sub>
- [An Absurd GitLab Avatar Bug](https://ten-dev-notes.blogspot.com/2024/02/gitlab-avatar.html) <sub>2024-02-28</sub>

</details>

<details>
<summary><b>2023</b> (50)</summary>

- [\[ Git \] A Look at a Branching Strategy Using git-flow](https://ten-dev-notes.blogspot.com/2023/12/git-git-flow.html) <sub>2023-12-13</sub>
- [\[ Spring \] What Is Spring Batch?](https://ten-dev-notes.blogspot.com/2023/12/spring-spring-batch.html) <sub>2023-12-07</sub>
- [\[ Spring \] Adding Swagger to Spring](https://ten-dev-notes.blogspot.com/2023/12/spring-spring-swagger.html) <sub>2023-12-07</sub>
- [\[ Spring \] Building a Java Web API Server](https://ten-dev-notes.blogspot.com/2023/12/spring-java-web-api-server.html) <sub>2023-12-07</sub>
- [\[ Spring \] Types of Annotations](https://ten-dev-notes.blogspot.com/2023/12/spring-annotation.html) <sub>2023-12-07</sub>
- [\[ Spring \] What Is Component Scan?](https://ten-dev-notes.blogspot.com/2023/12/spring-component-scan.html) <sub>2023-12-07</sub>
- [\[ Java \] The Java JVM](https://ten-dev-notes.blogspot.com/2023/12/java-java-jvm.html) <sub>2023-12-07</sub>
- [\[ Spring \] The Relationship Between the IoC Container and Beans](https://ten-dev-notes.blogspot.com/2023/12/spring-ioccontainer-bean.html) <sub>2023-12-07</sub>
- [\[ Git \] Automatically Updating Links to My Posts on GitHub](https://ten-dev-notes.blogspot.com/2023/11/git-githublink.html) <sub>2023-11-23</sub>
- [\[ Git \] How to Do Code Reviews with Git](https://ten-dev-notes.blogspot.com/2023/10/git-git.html) <sub>2023-10-17</sub>
- [\[ UrlDesign \] REST APIs and URL Design](https://ten-dev-notes.blogspot.com/2023/10/urldesign-restapi-url-design.html) <sub>2023-10-16</sub>
- [AWS Summit Notes](https://ten-dev-notes.blogspot.com/2023/10/aws.html) <sub>2023-10-06</sub>
- [Encryption Notes](https://ten-dev-notes.blogspot.com/2023/08/blog-post.html) <sub>2023-08-10</sub>
- [Setting Up a Git Token](https://ten-dev-notes.blogspot.com/2023/08/git-toekn.html) <sub>2023-08-10</sub>
- [\[ Mac \] ProxyCommand](https://ten-dev-notes.blogspot.com/2023/08/mac-proxycommand.html) <sub>2023-08-10</sub>
- [\[ Ngrok \] A Service for Accessing Localhost from the Outside](https://ten-dev-notes.blogspot.com/2023/08/ngrok-localhost-service.html) <sub>2023-08-03</sub>
- [\[ FCM \] Sending FCM Requests from the Server](https://ten-dev-notes.blogspot.com/2023/07/fcm-server-fcm.html) <sub>2023-07-26</sub>
- [\[ Edu \] Kindness and Diligence](https://ten-dev-notes.blogspot.com/2023/07/edu.html) <sub>2023-07-21</sub>
- [\[ Resume \] How to Show Notion Date Differences in Years, Months, and Days](https://ten-dev-notes.blogspot.com/2023/07/resume-notion.html) <sub>2023-07-16</sub>
- [\[ branding \] Why I Redesigned My Blog](https://ten-dev-notes.blogspot.com/2023/06/branding-blog.html) <sub>2023-06-21</sub>
- [\[ HR \] My Personal Take on the Hiring Process](https://ten-dev-notes.blogspot.com/2023/06/hr.html) <sub>2023-06-16</sub>
- [\[ aws \] Configuring a VPC for Elastic Beanstalk](https://ten-dev-notes.blogspot.com/2023/06/aws-eb-vpc.html) <sub>2023-06-15</sub>
- [\[ Aws \] How to Build a Bastion Host with EC2](https://ten-dev-notes.blogspot.com/2023/06/aws-ec2-bastion-host.html) <sub>2023-06-15</sub>
- [\[ aws \] How to Use scp with EC2](https://ten-dev-notes.blogspot.com/2023/06/aws-ec2-scp.html) <sub>2023-06-15</sub>
- [\[ aws \] How to Create a VPC with NAT](https://ten-dev-notes.blogspot.com/2023/06/aws-nat-vpc.html) <sub>2023-06-15</sub>
- [\[ aws \] How to Create Redis (ElastiCache)](https://ten-dev-notes.blogspot.com/2023/06/aws-rediselasticache.html) <sub>2023-06-15</sub>
- [How to Create a VPC on AWS](https://ten-dev-notes.blogspot.com/2023/06/aws-vpc.html) <sub>2023-06-15</sub>
- [\[ TroubleShooting \] Issues Caused by AWS RDS Automatic Updates](https://ten-dev-notes.blogspot.com/2023/06/troubleshooting-aws-rds.html) <sub>2023-06-02</sub>
- [An Auto-Upgrade Issue in AWS RDS](https://ten-dev-notes.blogspot.com/2023/05/aws-rds.html) <sub>2023-06-01</sub>
- [\[ Aws \] Restoring RDS from a Snapshot](https://ten-dev-notes.blogspot.com/2023/05/aws-rds-snapshot-restore-process.html) <sub>2023-05-22</sub>
- [AWS Snapshot Restore Process](https://ten-dev-notes.blogspot.com/2023/05/aws-snapshot-restore-process.html) <sub>2023-05-21</sub>
- [\[ Architecture \] How Startups Built Serverless Data Warehouses](https://ten-dev-notes.blogspot.com/2023/05/architecture.html) <sub>2023-05-14</sub>
- [AWS Summit Seoul 2023 Recap](https://ten-dev-notes.blogspot.com/2023/05/aws-summit-seoul-2023.html) <sub>2023-05-13</sub>
- [Topic: What Is the DIP?](https://ten-dev-notes.blogspot.com/2023/05/topic-what-is-dip.html) <sub>2023-05-12</sub>
- [\[ Architecture \] My Journey to Understanding OOP and SOLID](https://ten-dev-notes.blogspot.com/2023/05/architecture-oop-solid.html) <sub>2023-05-12</sub>
- [OOP and SOLID Explained](https://ten-dev-notes.blogspot.com/2023/05/oop-solid_01141124792.html) <sub>2023-05-12</sub>
- [\[ DesignPattern \] What Is SRP?](https://ten-dev-notes.blogspot.com/2023/05/designpattern-srp.html) <sub>2023-05-11</sub>
- [ISP: The Interface Segregation Principle](https://ten-dev-notes.blogspot.com/2023/05/isp.html) <sub>2023-05-11</sub>
- [LSP: The Liskov Substitution Principle](https://ten-dev-notes.blogspot.com/2023/05/lsp.html) <sub>2023-05-09</sub>
- [OCP: The Open-Closed Principle](https://ten-dev-notes.blogspot.com/2023/05/ocp-open-closed-principle.html) <sub>2023-05-09</sub>
- [Analyzing the API Gateway Pattern](https://ten-dev-notes.blogspot.com/2023/05/api-gateway-pattern.html) <sub>2023-05-04</sub>
- [Notes on OOP and SOLID](https://ten-dev-notes.blogspot.com/2023/05/oop-solid.html) <sub>2023-05-03</sub>
- [Naming Rules and Readability](https://ten-dev-notes.blogspot.com/2023/04/blog-post_26.html) <sub>2023-04-27</sub>
- [Reflections on Feedback Culture](https://ten-dev-notes.blogspot.com/2023/04/blog-post_254.html) <sub>2023-04-27</sub>
- [\[ Branding \] What Should Feedback Culture Look Like?](https://ten-dev-notes.blogspot.com/2023/04/branding.html) <sub>2023-04-20</sub>
- [\[ Code Convention \] Naming Variables](https://ten-dev-notes.blogspot.com/2023/04/blog-post.html) <sub>2023-04-20</sub>
- [\[ Django \] ORM Forward and Reverse References](https://ten-dev-notes.blogspot.com/2023/03/django-orm.html) <sub>2023-03-13</sub>
- [\[ Aws \] Django EB Deploy Settings](https://ten-dev-notes.blogspot.com/2023/01/aws-django-eb-deploy-setting.html) <sub>2023-01-18</sub>
- [\[ Slack \] Integrating Slack with Git](https://ten-dev-notes.blogspot.com/2023/01/slack-slack-git.html) <sub>2023-01-03</sub>
- [\[ Aws \] How to Create a CloudFront Distribution](https://ten-dev-notes.blogspot.com/2023/01/aws-cloudfront.html) <sub>2023-01-02</sub>

</details>

<details>
<summary><b>2022</b> (30)</summary>

- [\[ Aws \] Creating an S3 Bucket and Setting Permissions](https://ten-dev-notes.blogspot.com/2022/12/aws-s3.html) <sub>2022-12-30</sub>
- [\[ Aws \] Creating a Domain and Applying HTTPS](https://ten-dev-notes.blogspot.com/2022/12/aws-http-domain-https.html) <sub>2022-12-29</sub>
- [\[ Aws \] Setting Up Elastic Beanstalk](https://ten-dev-notes.blogspot.com/2022/12/aws-elastic-beanstalk.html) <sub>2022-12-28</sub>
- [\[ Aws \] Creating an EC2 Key Pair](https://ten-dev-notes.blogspot.com/2022/12/aws-ec2_01909927598.html) <sub>2022-12-28</sub>
- [\[ Django \] Bulk Create with the ORM](https://ten-dev-notes.blogspot.com/2022/12/django-orm-create-bulk.html) <sub>2022-12-27</sub>
- [\[ Aws \] Creating an EC2 Security Group](https://ten-dev-notes.blogspot.com/2022/12/aws-ec2.html) <sub>2022-12-12</sub>
- [\[ Architecture \] Why You Need a Ubiquitous Language](https://ten-dev-notes.blogspot.com/2022/11/architecture-ubiquitous-language.html) <sub>2022-11-14</sub>
- [\[ Edu \] 2023 Offline Backend Course for Beginners](https://ten-dev-notes.blogspot.com/2022/11/edu-2023-backend.html) <sub>2022-11-13</sub>
- [\[ HTTP \] HTTP Status Codes Summary](https://ten-dev-notes.blogspot.com/2022/09/http-http-status-code-tenlog.html) <sub>2022-09-02</sub>
- [\[ Django \] Creating a Django Prod Project](https://ten-dev-notes.blogspot.com/2022/09/django-django-prod.html) <sub>2022-09-02</sub>
- [\[ Django \] Key Django Commands](https://ten-dev-notes.blogspot.com/2022/08/django-django.html) <sub>2022-08-23</sub>
- [\[ Git \] Designing a Git Workflow When Starting a Project](https://ten-dev-notes.blogspot.com/2022/08/git-git.html) <sub>2022-08-22</sub>
- [\[ Node \] Receiving an EUC-KR Response in Node and Converting It to UTF-8](https://ten-dev-notes.blogspot.com/2022/08/node-node-euc-kr-response-utf-8.html) <sub>2022-08-22</sub>
- [\[ Django \] Customizing the Settings Structure to Manage Env Values](https://ten-dev-notes.blogspot.com/2022/08/django-env-settings.html) <sub>2022-08-22</sub>
- [\[ Django \] Debugging Django in VS Code](https://ten-dev-notes.blogspot.com/2022/08/django-django-debug-on-vscode.html) <sub>2022-08-19</sub>
- [\[ Django \] Logging in Django](https://ten-dev-notes.blogspot.com/2022/08/django-django-logging.html) <sub>2022-08-18</sub>
- [\[ AWS \] Using Lambda and Deploying with SAM](https://ten-dev-notes.blogspot.com/2022/06/aws-lambda-sam-deploy.html) <sub>2022-07-01</sub>
- [\[ Slack \] Sending Messages to Slack from a Node Server and Receiving Responses](https://ten-dev-notes.blogspot.com/2022/06/slack-node-slack.html) <sub>2022-06-10</sub>
- [\[ AWS \] Trying Out the Basics of Lambda](https://ten-dev-notes.blogspot.com/2022/05/aws-lambda.html) <sub>2022-05-27</sub>
- [\[ Typescript \] How to Debug TypeScript in VS Code](https://ten-dev-notes.blogspot.com/2022/05/typescript-vscode-typescript-debug-how.html) <sub>2022-05-11</sub>
- [\[ Node \] What Is the Node Event Loop](https://ten-dev-notes.blogspot.com/2022/04/node-node.html) <sub>2022-04-07</sub>
- [\[ Linux \] Setting Up Frontend, Backend, and DB Environments - My Own Node Deployment Process](https://ten-dev-notes.blogspot.com/2022/04/linux-node-db.html) <sub>2022-04-04</sub>
- [\[Coding Test\] Brute Force - Mock Exam in JS](https://ten-dev-notes.blogspot.com/2022/02/in-js.html) <sub>2022-02-22</sub>
- [\[Coding Test\] Distribute Candies to People in JS](https://ten-dev-notes.blogspot.com/2022/02/distribute-candies-to-people-in-js.html) <sub>2022-02-20</sub>
- [\[ MongoDB \] MongoDB Error (path":"/tmp/mongodb-27017.sock","error":"Operation not permitted")](https://ten-dev-notes.blogspot.com/2022/02/mongodb-mongodb-pathtmpmongodb.html) <sub>2022-02-17</sub>
- [\[AWS\] Creating an EC2 Instance and Logging In with SSH and a Password](https://ten-dev-notes.blogspot.com/2022/02/aws-ec2-ssh-password.html) <sub>2022-02-17</sub>
- [Setting Up and Using Database Replication on MariaDB](https://ten-dev-notes.blogspot.com/2022/01/mariadb-replication-how-to-use-database.html) <sub>2022-01-25</sub>
- [Setting Up and Using Load Balancing on Azure](https://ten-dev-notes.blogspot.com/2022/01/azure-load-balancing-how-to-set-load.html) <sub>2022-01-18</sub>
- [Setting Up and Using Load Balancing with Nginx](https://ten-dev-notes.blogspot.com/2022/01/nginx-load-balancing-how-to-set-load.html) <sub>2022-01-17</sub>
- [\[Coding Test - Stack/Queue\] Feature Development in JS](https://ten-dev-notes.blogspot.com/2022/01/in-js.html) <sub>2022-01-10</sub>

</details>

<details>
<summary><b>2021</b> (42)</summary>

- [Why isn't the Netherlands underwater? - 1](https://ten-dev-notes.blogspot.com/2021/12/why-isnt-netherlands-underwater-1.html) <sub>2021-12-30</sub>
- [How to Use DataLoader in GraphQL](https://ten-dev-notes.blogspot.com/2021/12/graphql-dataloader-how-to-use.html) <sub>2021-12-20</sub>
- [DB Indexes and B-Trees (How to Use Them)](https://ten-dev-notes.blogspot.com/2021/12/db-b-tree-how-to-use.html) <sub>2021-12-13</sub>
- [ERROR 1193 (HY000) at line 24: Unknown system variable 'GTID_PURGED' and Dump Commands](https://ten-dev-notes.blogspot.com/2021/11/error-1193-hy000-at-line-24-unknown.html) <sub>2021-11-22</sub>
- [ERROR 1273 (HY000) at line 49: Unknown collation: 'utf8mb4_0900_ai_ci'](https://ten-dev-notes.blogspot.com/2021/11/error-1273-hy000-at-line-49-unknown.html) <sub>2021-11-22</sub>
- [Let's Document Our Troubleshooting](https://ten-dev-notes.blogspot.com/2021/11/blog-post.html) <sub>2021-11-19</sub>
- [Resetting a Lost MariaDB/MySQL Root Password on Windows](https://ten-dev-notes.blogspot.com/2021/11/window-mariadb-mysql-root-password.html) <sub>2021-11-19</sub>
- [How to Use Triggers Easily in MySQL](https://ten-dev-notes.blogspot.com/2021/10/trigger-how-to-use-trigger-easily-in.html) <sub>2021-10-29</sub>
- [How to Install, Configure, and Run Nginx on CentOS 7](https://ten-dev-notes.blogspot.com/2021/10/nginx-how-to-install-and-use-nginx-on.html) <sub>2021-10-18</sub>
- [How to Use WebSocket in Node.js](https://ten-dev-notes.blogspot.com/2021/10/nodejs-web-socket.html) <sub>2021-10-18</sub>
- [How to Build an Electron App and Turn It into an Installer](https://ten-dev-notes.blogspot.com/2021/08/electron.html) <sub>2021-08-02</sub>
- [\[Coding Test\] String Compression in JS](https://ten-dev-notes.blogspot.com/2021/06/in-js.html) <sub>2021-06-02</sub>
- [\[Coding Test\] Intact Rectangles in JS](https://ten-dev-notes.blogspot.com/2021/05/in-js_0979806394.html) <sub>2021-05-23</sub>
- [\[Coding Test - Greedy\] Gym Clothes in Js](https://ten-dev-notes.blogspot.com/2021/05/in-js_02081960327.html) <sub>2021-05-22</sub>
- [\[Coding Test\] Phoneketmon in Js](https://ten-dev-notes.blogspot.com/2021/05/in-js_0549472715.html) <sub>2021-05-22</sub>
- [\[Coding Test - Dynamic Programming\] Expressing a Number with N in Js](https://ten-dev-notes.blogspot.com/2021/05/n-in-js.html) <sub>2021-05-22</sub>
- [\[Coding Test\] The Missing Fourth Point in Js](https://ten-dev-notes.blogspot.com/2021/05/in-js.html) <sub>2021-05-22</sub>
- [Making Async Calls Run Synchronously in Node.js (async-lock)](https://ten-dev-notes.blogspot.com/2021/05/nodejs-async-lock.html) <sub>2021-05-17</sub>
- [\[Trying Out RPA UiPath\] 2. A UiPath Test Run](https://ten-dev-notes.blogspot.com/2021/04/rpa-uipath-2-uipath.html) <sub>2021-04-21</sub>
- [\[Trying Out RPA UiPath\] 1. Installing the Free Version](https://ten-dev-notes.blogspot.com/2021/04/rpa-uipath-1.html) <sub>2021-04-21</sub>
- [What Is RPA?](https://ten-dev-notes.blogspot.com/2021/04/rpa.html) <sub>2021-04-21</sub>
- [\[Coding Test - Hash\] Camouflage in Java](https://ten-dev-notes.blogspot.com/2021/03/in-java.html) <sub>2021-03-05</sub>
- [About My Blog (Work in Progress)](https://ten-dev-notes.blogspot.com/2021/02/yeol.html) <sub>2021-02-27</sub>
- [Getting Started with AWS EC2 - Straight to a Running Instance](https://ten-dev-notes.blogspot.com/2021/02/aws-ec2.html) <sub>2021-02-17</sub>
- [\[Coding Test - Hash\] Phone Book in Java](https://ten-dev-notes.blogspot.com/2021/02/in-java_01451863205.html) <sub>2021-02-16</sub>
- [\[Coding Test - Hash\] The Runner Who Didn't Finish in Java](https://ten-dev-notes.blogspot.com/2021/02/in-java.html) <sub>2021-02-15</sub>
- [\[ubuntu\] Just Diving In and Running Docker](https://ten-dev-notes.blogspot.com/2021/02/ubuntu-docker.html) <sub>2021-02-05</sub>
- [Applying Fonts with CSS - Works in React, Vue, HTML, and More!](https://ten-dev-notes.blogspot.com/2021/02/react-vue-html-css-font.html) <sub>2021-02-03</sub>
- [A Quick Rundown of HTML Mouse Click Events](https://ten-dev-notes.blogspot.com/2021/02/html.html) <sub>2021-02-02</sub>
- [Resetting the Root Password on Ubuntu 18](https://ten-dev-notes.blogspot.com/2021/01/ubunto-18-root.html) <sub>2021-02-01</sub>
- [JavaScript Immutability, Explained Properly](https://ten-dev-notes.blogspot.com/2021/01/javascript.html) <sub>2021-01-29</sub>
- [CentOS 7 Firewall Commands, Explained](https://ten-dev-notes.blogspot.com/2021/01/centos7.html) <sub>2021-01-25</sub>
- [Super Simple: Disabling the Screensaver on CentOS 7](https://ten-dev-notes.blogspot.com/2021/01/centos-7.html) <sub>2021-01-20</sub>
- [Linux File Transfer Made Easy with WinSCP](https://ten-dev-notes.blogspot.com/2021/01/with-winscp.html) <sub>2021-01-13</sub>
- [Setting a Static IP on CentOS 7, the Simple Way](https://ten-dev-notes.blogspot.com/2021/01/centos7-ip.html) <sub>2021-01-12</sub>
- [Is It OK to Use jQuery in React?](https://ten-dev-notes.blogspot.com/2021/01/react-jquery.html) <sub>2021-01-10</sub>
- [Compiled vs. Interpreted Languages, Simply Explained!](https://ten-dev-notes.blogspot.com/2021/01/blog-post.html) <sub>2021-01-08</sub>
- [PuTTY - What It Is and How to Use It](https://ten-dev-notes.blogspot.com/2021/01/putty.html) <sub>2021-01-06</sub>
- [Really Easy! Using RTSP in React, Part 2](https://ten-dev-notes.blogspot.com/2021/01/react-rtsp-2.html) <sub>2021-01-04</sub>
- [JavaScript in Under a Minute](https://ten-dev-notes.blogspot.com/2021/01/javascript-1.html) <sub>2021-01-03</sub>
- [Building a Calendar in React with Moment.js, the Easy Way](https://ten-dev-notes.blogspot.com/2021/01/react-with-momentjs.html) <sub>2021-01-02</sub>
- [HTML5 in Under a Minute](https://ten-dev-notes.blogspot.com/2021/01/html5-1.html) <sub>2021-01-01</sub>

</details>

<details>
<summary><b>2020</b> (56)</summary>

- [\[HR\] How Non-CS Majors Around Me Got into IT Jobs](https://ten-dev-notes.blogspot.com/2020/12/hr-it.html) <sub>2020-12-31</sub>
- [Super Simple! Using jQuery in React](https://ten-dev-notes.blogspot.com/2020/12/react-jquery.html) <sub>2020-12-30</sub>
- [Super Simple!! Backing Up and Restoring PostgreSQL 11 with pgAdmin](https://ten-dev-notes.blogspot.com/2020/12/postgresql-11-backup-restore-with.html) <sub>2020-12-28</sub>
- [Uncaught SyntaxError: Unexpected token '<'](https://ten-dev-notes.blogspot.com/2020/12/uncaught-syntaxerror-unexpected-token.html) <sub>2020-12-23</sub>
- [Super Simple! How to Make a CentOS Bootable USB](https://ten-dev-notes.blogspot.com/2020/12/centos-usb.html) <sub>2020-12-22</sub>
- [Some Thoughts on School Education](https://ten-dev-notes.blogspot.com/2020/12/blog-post.html) <sub>2020-12-03</sub>
- [The Linux tar Command Made Easy](https://ten-dev-notes.blogspot.com/2020/11/linux-tar.html) <sub>2020-11-24</sub>
- [Should You Get the Big Data Analysis Engineer Certification?](https://ten-dev-notes.blogspot.com/2020/11/blog-post.html) <sub>2020-11-23</sub>
- [A Simple Guide to Using the Google Maps API with React](https://ten-dev-notes.blogspot.com/2020/11/react-google-map-api.html) <sub>2020-11-12</sub>
- [How to Send Values from React to Express, Part 2](https://ten-dev-notes.blogspot.com/2020/11/react-express-2.html) <sub>2020-11-10</sub>
- [A Simple Guide to Installing CentOS 7 on Windows](https://ten-dev-notes.blogspot.com/2020/10/centos-7.html) <sub>2020-10-30</sub>
- [How to Read HTTP Header Values in Express, Koa, and the Browser](https://ten-dev-notes.blogspot.com/2020/10/blog-post_21.html) <sub>2020-10-21</sub>
- [Super Simple! Install Python and Run It in Atom](https://ten-dev-notes.blogspot.com/2020/10/python-atom.html) <sub>2020-10-21</sub>
- [Really Easy! Using RTSP in React, Part 1](https://ten-dev-notes.blogspot.com/2020/10/react-rtsp-1.html) <sub>2020-10-20</sub>
- [How to Install Node.js on CentOS 7](https://ten-dev-notes.blogspot.com/2020/10/centos7-nodejs-how-to-install-nodejs-on.html) <sub>2020-10-13</sub>
- [Cookies and Sessions, Explained Simply](https://ten-dev-notes.blogspot.com/2020/10/cookie-session.html) <sub>2020-10-06</sub>
- [Getting the Date and Time Without a Time Zone in PostgreSQL](https://ten-dev-notes.blogspot.com/2020/09/postgresql-without-timezone.html) <sub>2020-09-25</sub>
- [Setting Up HTTPS in Node.js with OpenSSL](https://ten-dev-notes.blogspot.com/2020/09/nodejs-openssl.html) <sub>2020-09-24</sub>
- [Local HTTPS with OpenSSL: Self-Signed Certificates for Node.js and React](https://ten-dev-notes.blogspot.com/2020/09/ssl.html) <sub>2020-09-17</sub>
- [PostgreSQL Data Types Cheat Sheet](https://ten-dev-notes.blogspot.com/2020/09/postgresql.html) <sub>2020-09-16</sub>
- [Redux-Saga Effects, Explained Simply](https://ten-dev-notes.blogspot.com/2020/09/redux-saga.html) <sub>2020-09-10</sub>
- [How I Studied for and Passed the JLPT N2](https://ten-dev-notes.blogspot.com/2020/08/jlpt-n2.html) <sub>2020-08-27</sub>
- [The Simplest Way to Set Up FTP Downloads on CentOS 7](https://ten-dev-notes.blogspot.com/2020/08/centos-7-ftp.html) <sub>2020-08-26</sub>
- [How I Passed the Engineer Information Processing Certification (2019, Round 3)](https://ten-dev-notes.blogspot.com/2020/08/2019-3.html) <sub>2020-08-19</sub>
- [What I Learned About JS Syntax and ES6](https://ten-dev-notes.blogspot.com/2020/08/js-es6.html) <sub>2020-08-12</sub>
- [Express vs Koa - The Differences at a Glance](https://ten-dev-notes.blogspot.com/2020/08/express-koa.html) <sub>2020-08-11</sub>
- [React Inputs, Explained Simply](https://ten-dev-notes.blogspot.com/2020/08/react-input.html) <sub>2020-08-10</sub>
- [Setting Up Korean Input on Ubuntu 18.04](https://ten-dev-notes.blogspot.com/2020/07/ubuntu-1804.html) <sub>2020-07-20</sub>
- [Port Forwarding with VMware 15.5 and CentOS 7](https://ten-dev-notes.blogspot.com/2020/07/vmware-155-centos-7.html) <sub>2020-07-17</sub>
- [Running Ubuntu Desktop on VMware the Easy Way](https://ten-dev-notes.blogspot.com/2020/07/vmware-ubuntu.html) <sub>2020-07-17</sub>
- [Installing PostgreSQL the Easy Way](https://ten-dev-notes.blogspot.com/2020/07/postgresql.html) <sub>2020-07-16</sub>
- [How to Install VMware - A Quick Guide](https://ten-dev-notes.blogspot.com/2020/07/vmware.html) <sub>2020-07-08</sub>
- [Getting Started with Koa for Node.js](https://ten-dev-notes.blogspot.com/2020/07/nodejs-koa.html) <sub>2020-07-07</sub>
- [Understanding Redux Data Flow in React, Part 2](https://ten-dev-notes.blogspot.com/2020/06/react-redux-2.html) <sub>2020-06-17</sub>
- [Understanding Redux Data Flow in React, Part 1](https://ten-dev-notes.blogspot.com/2020/06/react-redux-1.html) <sub>2020-06-17</sub>
- [Understanding the React Context API](https://ten-dev-notes.blogspot.com/2020/06/react-context-api.html) <sub>2020-06-15</sub>
- [Thoughts on YouTube Shopping](https://ten-dev-notes.blogspot.com/2020/06/youtube.html) <sub>2020-06-13</sub>
- [No Better Explanation Than This! Using the Router in React!](https://ten-dev-notes.blogspot.com/2020/06/react-router.html) <sub>2020-06-12</sub>
- [Thoughts on CSS and Sass in React](https://ten-dev-notes.blogspot.com/2020/06/react-css-sass.html) <sub>2020-06-11</sub>
- [Using the NCP SMS API with Node.js](https://ten-dev-notes.blogspot.com/2020/06/ncp-sms-api-nodejs.html) <sub>2020-06-11</sub>
- [React Hooks Made Easy, Part 2!](https://ten-dev-notes.blogspot.com/2020/06/hooks-2.html) <sub>2020-06-11</sub>
- [React Hooks Made Easy!](https://ten-dev-notes.blogspot.com/2020/06/hooks.html) <sub>2020-06-11</sub>
- [How to Pass Values from React to Express, Part 1](https://ten-dev-notes.blogspot.com/2020/06/react-express-1.html) <sub>2020-06-05</sub>
- [The Quickest Way to Install and Run React.js](https://ten-dev-notes.blogspot.com/2020/06/reactjs.html) <sub>2020-06-05</sub>
- [A Quick Hands-On with Node.js and PostgreSQL, Part 3](https://ten-dev-notes.blogspot.com/2020/06/nodejs-postgresql-3.html) <sub>2020-06-05</sub>
- [Getting Started with Node.js and PostgreSQL, Part 2](https://ten-dev-notes.blogspot.com/2020/05/nodejs-postgresql-2.html) <sub>2020-05-26</sub>
- [Learning Ant Design with React (Dashboard), Part 5](https://ten-dev-notes.blogspot.com/2020/05/react-ant-dashboard-5.html) <sub>2020-05-26</sub>
- [Learning Ant Design with React (Dashboard), Part 4](https://ten-dev-notes.blogspot.com/2020/05/react-ant-dashboard-4.html) <sub>2020-05-26</sub>
- [Learning Ant Design with React (Dashboard), Part 3](https://ten-dev-notes.blogspot.com/2020/05/react-ant-dashboard-3.html) <sub>2020-05-25</sub>
- [Learning Ant Design with React (Dashboard), Part 2](https://ten-dev-notes.blogspot.com/2020/05/react-ant-dashboard-2.html) <sub>2020-05-25</sub>
- [Learning Ant Design with React (Dashboard), Part 1](https://ten-dev-notes.blogspot.com/2020/05/react-ant-dashboard-1.html) <sub>2020-05-25</sub>
- [Getting Started with Node.js and PostgreSQL, Part 1](https://ten-dev-notes.blogspot.com/2020/05/nodejs-postgresql-1.html) <sub>2020-05-22</sub>
- [JS Syntax I Didn't Know: If a\[b\] = "c", Then console.log(a) Prints {b:"c"}](https://ten-dev-notes.blogspot.com/2020/05/js-ab-c-consoleloga-bc.html) <sub>2020-05-21</sub>
- [Why Use async and await? A Simple Explanation with JS](https://ten-dev-notes.blogspot.com/2020/05/async-await-with-js.html) <sub>2020-05-21</sub>
- [Node.js Environment Variables, Simply Explained (and How to Set Them)](https://ten-dev-notes.blogspot.com/2020/05/nodejs_01563591673.html) <sub>2020-05-21</sub>
- [What Is Node.js? A Quick Intro and How to Install It](https://ten-dev-notes.blogspot.com/2020/05/nodejs.html) <sub>2020-05-21</sub>

</details>
<!-- posts:end -->
