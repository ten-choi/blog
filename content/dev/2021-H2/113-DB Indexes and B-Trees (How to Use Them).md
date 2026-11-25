---
title: "DB Indexes and B-Trees (How to Use Them)"
labels: ["DB","rdb","B-tree","SQL","Archive"]
published: true
date: 2021-12-13T15:39:10+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 113
tistoryUrl: "https://yeolceo.tistory.com/113"
tistoryCategory: "DB/rdb"
tistoryTags: ["B-tree","SQL","DB"]
tistoryPostedAt: "2021-12-13 15:39:10"
language: en
bloggerPostId: "6735386224323188082"
---
Glossary

Full Scan: reads every record in the table from start to finish.

```html
explain SELECT * FROM table_name;
```

Range Scan: reads only some of the records in the table.

```html
explain SELECT * FROM table_name where no > 1 and no < 5;
```

Index Scan: (if you've registered an index column) fetches records by evaluating the condition against the index.

```html
explain SELECT * FROM table_name where index_column = 'value'
```

Duration: the time it takes to execute the query. The lower, the better for performance.

Fetch: the time spent retrieving the query results. It reflects network performance.

### **What Is an Index**

It's one of the techniques for improving search performance in an RDBMS. Data is sorted by key value, and searching sorted data is faster.

Using SELECT with a WHERE clause without an index results in a full scan. With an index, the search goes through an index range scan, which narrows the area being searched and speeds things up. That said, past a certain amount of data, a full scan can actually be better.

Pros

1.  You can improve performance without changing your SQL. 
2.  It doesn't affect the data in the table. 
3.  You can expect a consistent (sometimes dramatic) effect. 

**Cons**

But if data changes frequently, every insert means the existing index has to be rebuilt, which hurts performance.

Rebuilding the index counts against DB performance, so overusing indexes puts load on the database.

Criteria for creating one

**1\. Only create them on large tables.** 

**3\. Create them on columns with high cardinality.** 

### **B-Tree (Balanced Tree) Index**

There's a root node at the top, with branch nodes extending below it. The nodes at the very bottom are called leaf nodes.

The index and the actual data are managed separately, and the index's leaf nodes always hold the address used to find the actual data record.

Once the storage location is decided, the record's key value and the target record's address are stored in a B-Tree leaf node. If a leaf node is full and can't hold any more, it has to be split, and that can ripple up to the branch nodes above. That's why writes are expensive.

### **Usage**

Creating an index also counts against DB performance.

Check whether a table has indexes

```html
show index from table_name;
```

Add an index to a table 

```html
create index testindex on  WORK_DAILY_SEQ (CAR_NUM);
ALTER TABLE table_name ADD INDEX index_name USING BTREE (column_to_index);
```

```html
ALTER TABLE table_name ADD INDEX index_name USING BTREE (column_to_index);
```

```html
ALTER TABLE table_name ADD INDEX index_name USING BTREE (column_to_index);
```

```html
ALTER TABLE table_name ADD INDEX index_name USING BTREE (column_to_index);
```

### **When Running with an Index**

When you run with an index, comparing a scan using the index against a plain range scan and a full scan 

### **Rebuilding Indexes**

Apparently, doing inserts, updates, and deletes (anything other than searches) can make one side of the tree heavy, which can lead to worse performance.

Since that slows down searches, the index needs to be rebuilt periodically.

Why indexes aren't just plain arrays

![Source: https://www.geeksforgeeks.org/search-insert-and-delete-in-a-sorted-array/](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/113/img.webp)

References

[https://zorba91.tistory.com/292](https://zorba91.tistory.com/292)
