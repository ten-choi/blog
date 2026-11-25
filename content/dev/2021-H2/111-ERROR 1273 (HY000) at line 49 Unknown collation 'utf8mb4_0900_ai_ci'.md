---
title: "ERROR 1273 (HY000) at line 49: Unknown collation: 'utf8mb4_0900_ai_ci'"
labels: ["TroubleShooting","SQL","mysql","Archive"]
published: true
date: 2021-11-22T13:50:42+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 111
tistoryUrl: "https://yeolceo.tistory.com/111"
tistoryCategory: "TroubleShooting/SQL"
tistoryTags: ["Unknown","mysql","mysql"]
tistoryPostedAt: "2021-11-22 13:50:42"
language: en
bloggerPostId: "7137363029756788200"
---
## **Documentation**

Situation  
I hit the error above while dumping a database and restoring it.

**1\. Define the problem**

It says utf8mb4\_0900\_ai\_ci is an unknown collation.

```html
ERROR 1273 (HY000) at line 49: Unknown collation: 'utf8mb4_0900_ai_ci'
```

**2\. Find the root cause**

The dump came from a partner company's MySQL 8.0 on Linux into my local MySQL 8.0 on Windows, so a charset mismatch looks like the culprit.

**3\. Fix and test**

After some searching, I added a utf8mb4 charset option to the dump command and tested it.  

```html
mysqldump -u xxxx  -h xxxx -p  --set-gtid-purged=OFF --default-character-set=utf8mb4  xxxxdbname > C:/Users/xxxx/Dump2022xxxx.sql
```

**4\. Apply**

The dump file imported successfully.

```html
Import of C:xxx/xxx/Dump20211122.sql has finished
```
