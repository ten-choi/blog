---
title: "ERROR 1193 (HY000) at line 24: Unknown system variable 'GTID_PURGED' and Dump Commands"
labels: ["TroubleShooting","SQL","gtid_purged","mysql","Archive"]
published: true
date: 2021-11-22T14:06:01+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 112
tistoryUrl: "https://yeolceo.tistory.com/112"
tistoryCategory: "TroubleShooting/SQL"
tistoryTags: ["gtid_purged","Unknown","mysql","mysql"]
tistoryPostedAt: "2021-11-22 14:06:01"
language: en
bloggerPostId: "3147488123976934954"
---
## **Documentation**

Situation  
I hit the error above while dumping a database and restoring it.

**1\. Define the problem**

It says GTID\_PURGED is an unknown system variable. GTID stands for Global Transaction Identifier, the ID value of a transaction.

```html
ERROR 1193 (HY000) at line 24: Unknown system variable 'GTID_PURGED'
```

**2\. Find the root cause**

The error happens when bringing a dump from a partner company's MySQL 8.0 on Linux into my local MySQL 8.0 on Windows, or into MariaDB 10.3. It seems to occur when you restore a dump into a version that doesn't support GTIDs.

**3\. Fix and test**

 Option 1: add --set-gtid-purged=OFF when you run the dump command.

```html
mysqldump -u xxxx  -h xxxx -p  --set-gtid-purged=OFF  xxxxdbname > C:/Users/xxxx/Dump20211122.sql
```

 Option 2: open the dump file as text, delete the line that looks like 'SET @@GLOBAL.GTID\_PURGED', and then restore the dump.

**4\. Apply**

Both approaches just get rid of GTID\_PURGED, and the dump restored without any problems.

```html
Import of C:xxx/xxx/Dump20211123.sql has finished
```

#Update after searching for this again after a long time, based on MySQL 8.0 -> 22.05.12  
For the record, I forgot that the angle bracket points the other way for restoring and wasted an hour..

```bash
./mysqldump --set-gtid-purged=OFF -h 'localhost' -u root -p test-db > /Users/yeol/workspace/dump/DB_Backup.dump
./mysql -u root -p test-db < /Users/yeol/workspace/dump/DB_Backup.dump
```
