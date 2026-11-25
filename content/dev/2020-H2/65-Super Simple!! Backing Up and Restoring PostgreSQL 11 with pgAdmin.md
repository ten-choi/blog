---
title: "Super Simple!! Backing Up and Restoring PostgreSQL 11 with pgAdmin"
labels: ["DB","rdb","postgresql","postgres","Archive"]
published: true
date: 2020-12-28T16:50:38+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 65
tistoryUrl: "https://yeolceo.tistory.com/65"
tistoryCategory: "DB/rdb"
tistoryTags: ["postgresql","postgres","postgresql","postgres","postgres"]
tistoryPostedAt: "2020-12-28 16:50:38"
language: en
bloggerPostId: "6187098831635333253"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img-png.webp)

#### Since we're using pgAdmin, this backup and restore method is easy to learn!!

## **1\. Create a PostgreSQL DB**

#### First, launch pgAdmin. (You'll need to have it installed beforehand...!)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_1-png.webp)

#### Following the image below, right-click -> Create -> Database... in that order.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_2-png.webp)

#### I named the database forbackup — I wanted the name to say it's for backups.

#### And just like that, the forbackup DB is ready! Let's create a table right away.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img.webp)

#### We'll create the table with a query.

#### Following the image below, right-click Tables and open the Query Tool.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_3-png.webp)

#### Use the code below to create the table.

```html
CREATE TABLE tb_test (
  "seq" SERIAL not null PRIMARY KEY,
  "age" integer not null,
  "name" character varying(32) not null
);
```

#### If it worked, check the table you just created by following the image below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_4-png.webp)

#### Enter some data. (Let's just do this much by hand... two rows is enough...)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_5.webp)

#### Just like that, your DB table has rows and columns.

## **2\. Back Up the PostgreSQL DB**

#### Now let's start the backup.

#### Right-click the forbackup DB and select Backup from the list.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_6.webp)

#### The pre-backup settings screen will pop up.

#### Click the area I outlined with the pink box. This is where you set the save path and backup file name.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_7.webp)

#### I created a folder called bk\_File on my desktop.

#### I'll use dump1 as the backup file name. Set the format below to sql.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_1.webp)

#### Set the backup format type to Tar. (tar is one of the archive formats used on Linux.)

#### When you're done, click the Backup button to run the backup.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_2.webp)

#### Congratulations — the backup was a breeze. If you look inside the folder you created,

#### you'll find a file named after your file name, with a .sql extension.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_3.webp)

## **3\. Restore the PostgreSQL DB**

#### No time to rest. Let's go straight to creating a database called forrestore.

#### The steps are the same as before, and I picked the name to make it obvious it's the restore DB. (Names matter.)

#### Right-click the new database to bring up the window below.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_8.webp)

#### The default on the first line matches the format we set, so leave it as is.

#### To find the backup file, go straight to the second line. Click the three-dot button above the red line on the right!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_9.webp)

#### Find the dump1 file we saved earlier and select it!!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_4.webp)

#### Nothing else to touch — just hit the Restore button to wrap it up.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_10.webp)

#### Did you get a success message like the one below?

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_11.webp)

#### If you check, you'll see tb\_test in the forrestore DB.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/65/img_12.webp)

#### And that's it — a quick and easy backup and restore.

#### If it all worked, congratulations. Happy coding!
