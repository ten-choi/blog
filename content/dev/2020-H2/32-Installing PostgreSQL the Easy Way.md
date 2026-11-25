---
title: "Installing PostgreSQL the Easy Way"
labels: ["DB","rdb","PostgreSQL","Archive"]
published: true
date: 2020-07-16T13:33:00+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 32
tistoryUrl: "https://yeolceo.tistory.com/32"
tistoryCategory: "DB/rdb"
tistoryTags: ["PostgreSQL","postgresql","postgresql"]
tistoryPostedAt: "2020-07-16 13:33:00"
language: en
bloggerPostId: "7619077862800503198"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img.webp)

## \- What Is PostgreSQL?

It's a type of relational database. Why am I using it? Because I was told to use PostgreSQL. Typical RDBs are all managed with SQL, so which DB you pick is up to you.

## \- Downloading the PostgreSQL Installer

Just go to the PostgreSQL site and install it. I've left the link below; I clicked the part I've highlighted

to download it (64-bit). I picked 11 rather than the latest because I wanted the more stable version one step

below it. Feel free to go with 12 if you prefer.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_1.webp)

[https://www.enterprisedb.com/downloads/postgres-postgresql-downloads](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads)

## \- Installation Steps

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_2.webp)

The installer starts.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_3.webp)

These are the PostgreSQL server and management tools.

Stack Builder is used to install tools, drivers, apps, and so on that complement PostgreSQL, but I don't use it.

Uncheck it.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_4.webp)

If your disk is split into partitions, change this to whatever path you want.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_5.webp)

\*I strongly recommend saving your password separately, for example in a text file.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_6.webp)

PostgreSQL uses port 5432 by default.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_7.webp)

Use the default locale. There's no reason to pick anything special.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_8.webp)

Wait for the installation to finish.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/32/img_9.webp)

Uncheck Stack Builder and click Finish.

Congrats! That's PostgreSQL installed, and it couldn't be easier.

Now that it's installed, let's get it running.

[https://yeolceo.tistory.com/7?category=919564](https://yeolceo.tistory.com/7?category=919564)
