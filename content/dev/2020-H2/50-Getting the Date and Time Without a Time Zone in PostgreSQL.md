---
title: "Getting the Date and Time Without a Time Zone in PostgreSQL"
labels: ["DB","rdb","postgresql","Archive"]
published: true
date: 2020-09-25T16:45:31+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 50
tistoryUrl: "https://yeolceo.tistory.com/50"
tistoryCategory: "DB/rdb"
tistoryTags: ["postgresql","postgresql","postgresql"]
tistoryPostedAt: "2020-09-25 16:45:31"
language: en
bloggerPostId: "5012682047065667821"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/50/img.webp)

## **\- Short and sweet: just two statements -**

select to\_char(now(), 'YYYY-MM-DD HH:MI:SS')                     Just the date and time -> no fractional seconds or time zone

select now()+'-5 minute' where now()+'-5 minute' > now()     For fetching a value offset from now by \[days, minutes, seconds\]

With just these two statements, you can handle most time-related tasks in PostgreSQL.

I hope this helps someone. If you know a better way, feel free to point it out anytime.

Thanks!
