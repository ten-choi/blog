---
title: "MySQL Performance Optimization - Hands-on Test with 12 Million Rows"
labels: ["database","rdb","mysql","optimization","Archive"]
published: true
date: 2024-10-01T18:56:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "8005591364831844339"
source: "archive"
archivePath: "_archive/dev/database/mysql optimzize index and algorithm.md"
---



I'm going to walk through the problems I ran into, and the performance I got, when handling a large amount of data in a single table.


I created a table that uses a Snowflake ID as its key.
The table is called article.
I loaded 12 million rows into the article table and then checked the performance.


![NotionImage](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/mysql-optimzize-index-and-algorithm/img.webp)





```sql
select * from article where board_id = 1 order by created_at desc limit 30 offset 90;
```


![NotionImage](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/mysql-optimzize-index-and-algorithm/img_1.webp)

A better machine would probably do better, but mine took 27 seconds.

That's far too slow to be usable. So how do we fix it?





```sql
create index idx_board_id_article_id on article(board_id asc,
article_id desc);
```

![NotionImage](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/mysql-optimzize-index-and-algorithm/img_2.webp)


![NotionImage](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/mysql-optimzize-index-and-algorithm/img_3.webp)


![NotionImage](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/mysql-optimzize-index-and-algorithm/img_4.webp)


I checked the execution time, the key used, and the access type.
So it works. But is that the end of it? Did creating an index solve the problem?

The answer is no.
Let me show you what happens when I change the offset value.


![NotionImage](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/mysql-optimzize-index-and-algorithm/img_5.webp)


It's way too slow, so I checked the query plan, but nothing had changed.

```sql
mysql> explain select * from article where board_id = 1 order by article_id desc limit 30 offset 1499970;
```

![NotionImage](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/mysql-optimzize-index-and-algorithm/img_6.webp)



In MySQL,
InnoDB is the default storage engine.

Its four defining features are said to be
transactions, foreign keys, concurrency control (locking), and crash recovery.

On top of that, InnoDB uses the primary key as a clustered index.

So when you query by article_id, which is the primary key, you're using the clustered index that InnoDB creates automatically.

If you look at this picture, that query is very fast.
So why is it so fast?

![NotionImage](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/mysql-optimzize-index-and-algorithm/img_7.webp)

Because we're using the primary key.
We didn't create it ourselves; in InnoDB, the primary key automatically gets a clustered index.

![NotionImage](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/mysql-optimzize-index-and-algorithm/img_8.webp)


An index that we create ourselves is called a secondary index (or non-clustered index).

Its leaf nodes hold the indexed column data and a pointer for accessing the clustered index.

Because a secondary index depends on the clustered index,

a lookup first finds the indexed columns in the secondary index's leaf nodes, then matches them to the clustered index's ID to find the row.


In the query below, MySQL has to keep going back and forth between the clustered index and the secondary index all the way until it reaches the offset, because of the order by.

```sql
select * from article where board_id = 1 order by article_id desc limit 30 offset 1499970;
```

1. Scan the rows matching WHERE board_id = 1 in order through the idx_board_id_article_id index
2. Fetch rows one by one, keeping the article_id DESC order
3. Discard as many rows as the OFFSET (skip 1,499,970 rows)
4. Return only the next 30 rows (LIMIT) as the SELECT result

In other words, it reads and throws away 1,499,970 rows from the start, then returns the next 30.
This is known as "offset hell."


So what do people do in practice?
They use an approach called keyset pagination (or the seek method), which avoids offset entirely and reads only the part that's needed.

```sql
-- First request
SELECT * FROM article 
WHERE board_id = 1 
ORDER BY article_id DESC 
LIMIT 30;

-- Next request
SELECT * FROM article 
WHERE board_id = 1 
  AND article_id < {last article_id from the previous page}
ORDER BY article_id DESC 
LIMIT 30;
```


There's also something called a covering index.
It's an index that can serve all the data a query needs by itself,
meaning the query can be answered from the secondary index alone, without going to the clustered index.


But if the offset grows large and you really do need that functionality, you have to solve it another way:
for example, skipping by year, or partitioning the table to split the data.
If the data volume itself is huge, that kind of approach is an option.

Sometimes it's solved with policy instead.
You can decide that a normal user wouldn't be pulling data that old, and either restrict it or
offer range-based search instead.

Logically, something like infinite scroll can keep query speed consistent even on later pages, but with this much data it may not be the approach to adopt.


If you implement paging as infinite scroll:

when new pages are created or deleted, you can get duplicates or missing items while browsing.
Infinite scroll fetches the next batch based on the ID of the last item it loaded.




Find all valid combinations of k numbers that sum up to n such that the following conditions are true:

Only numbers 1 through 9 are used.
Each number is used at most once.
Return a list of all possible valid combinations. The list must not contain the same combination twice, and the combinations may be returned in any order.
