---
title: "AWS Snapshot Restore Process"
labels: ["aws rdb","snapshot restore","Archive"]
published: true
date: 2023-05-21T10:00:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "8478135805439458333"
source: "blogger"
sourceBlog: "https://ten-logged.blogspot.com/"
sourcePostId: "6214511176349014941"
sourceStatus: LIVE
sourceUrl: "https://ten-logged.blogspot.com/2023/05/aws-snapshot-restore-process.html"
sourcePublishedAt: "2023-05-21T21:08:00-07:00"
---
#### **Topic: How to restore rdb from snapshot**

AWS RDS has a system that automatically backs up every day  
That backup data is called a snapshot  
So how do you bring back the RDB data you backed up as a snapshot?  
Let's look at the RDS settings in AWS

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/aws-snapshot-restore-process/img.webp)

  

Click Snapshots in the left-hand menu shown in the image above  
You'll see a list of automatically created snapshots

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/aws-snapshot-restore-process/img_1.webp)

  

Click Restore snapshot using the button on the right  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/aws-snapshot-restore-process/img_2.webp)

  

Just go with the preset settings  
Set the RDB version to match the RDB you're restoring

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/archive/aws-snapshot-restore-process/img_3.webp)

Make sure to set Public access above to Yes  
Otherwise, nothing outside of EC2 can connect to it

After that, keep the defaults  
and click Restore DB cluster, the button at the very bottom, and you're done

A new RDB instance is created  
The backup data stored in the snapshot is in that instance  
Creating the instance takes a long time, so it's best to do it carefully and avoid mistakes

If everything above went well, there are a few things to watch out for

1.  There's a button called Export to Amazon S3  
    Don't use it  
    It exports the data to S3 in Parquet format  
    The export takes a long time, and the files are a pain to work with
2.  If you look at the snapshot list, a single row gets updated  
    It gets overwritten the next day, so make a copy before you start
3.  Once you've created it and gotten your data, delete the RDS instance right away  
    It costs money
