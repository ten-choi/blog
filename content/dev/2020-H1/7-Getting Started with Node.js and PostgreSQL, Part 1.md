---
title: "Getting Started with Node.js and PostgreSQL, Part 1"
labels: ["DB","rdb","PostgreSQL","Archive"]
published: true
date: 2020-05-22T17:32:01+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 7
tistoryUrl: "https://yeolceo.tistory.com/7"
tistoryCategory: "DB/rdb"
tistoryTags: ["PostgreSQL","postgresql","postgresql"]
tistoryPostedAt: "2020-05-22 17:32:01"
language: en
bloggerPostId: "3675706724764352080"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/7/img.webp)

To put it very simply, PostgreSQL is an RDB that's been around for a long time.

If you don't know the difference between RDBs and NoSQL, I recommend Googling it to get the concept down.

Personally, I didn't notice much difference from MySQL or Oracle.

(I just used it as a database without needing a deep understanding. At least that was my experience.)

I'd guess you'd use a DB more on outside projects than on personal side projects.

[https://www.enterprisedb.com/downloads/postgres-postgresql-downloads](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads)

Here's the link. Just download the 64-bit Windows version.

You can skip Stack Builder during the install. I never needed it.

I recommend saving the key info you enter during installation in a separate text file.

(e.g.   pgReadMe.txt  ->   password : asdf       port : 5432) If something looks like you'll need it later, write it down.

Getting into the habit of writing things down really helps.

Once everything's installed, search for pgadmin in the Windows search bar and you'll see the executable.

**Now let's search for pgadmin in Windows.**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/7/img_1.webp)

Just search for pgadmin here. Simple.

Click the executable that shows up.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/7/img_2.webp)

A screen like this opens in your browser. If you followed along above, enter the password you saved in your text file.

Most people pick a password that's easy for them, so just enter the one you set during installation.

(On the off chance you're someone who keeps your PC really tidy, you may have stopped the PostgreSQL service  
so it doesn't eat RAM. But if it's stopped, the DB won't start, so keep that in mind. I'm tidy like that, so I had stopped it.)

**And just like that, it's running.**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/7/img_3.webp)

Click through the list as it appears and you'll get the same screen as mine.

You can create databases, schemas, and tables just by right-clicking and choosing Create.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/7/img_4.webp)

Just set a name, hit Save, and your table is done.

Of course, you can also create columns by right-clicking on a table. Super simple.

At the very bottom of the right-click menu there's the Query Tool for SQL, so you can write it yourself if you prefer!

That's a really quick tour of how to use PostgreSQL. That's all there is to it.

In the next post, I'll connect it to Node.js.

I'll be using PostgreSQL in a Node.js environment with the Atom editor.
