---
title: "[ MongoDB ] MongoDB Error (path\":\"/tmp/mongodb-27017.sock\",\"error\":\"Operation not permitted\")"
labels: ["TroubleShooting","mongoDB","Operation","Archive"]
published: true
date: 2022-02-17T12:38:25+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 125
tistoryUrl: "https://yeolceo.tistory.com/125"
tistoryCategory: "TroubleShooting"
tistoryTags: ["mongoDB","Operation"]
tistoryPostedAt: "2022-02-17 12:38:25"
language: en
bloggerPostId: "621375691844301988"
---
#### Environment

Aws  
RedHat 8  
MongoDB 4.4

#### Overview

Troubleshooting an error that shows up when you install and run MongoDB on RedHat.

## \- Fix

This happens when there's a permission problem with the sock file. I tried resetting permissions for the mongod user on every file and folder that might not have picked them up, but that didn't fix it. I ended up solving it with help from Stack Overflow.

Mongo error log  

```html
{"t":{"$date":"2022-02-10T00:44:16.121+00:00"},"s":"E",  "c":"NETWORK",  "id":23024,  
"ctx":"initandlisten","msg":"Failed to unlink socket file",
"attr":{"path":"/tmp/mongodb-27017.sock","error":"Operation not permitted"}}
```

## for Linux

```
$ sudo rm -rf /tmp/mongodb-27017.sock
$ sudo service mongod start
```

[https://stackoverflow.com/questions/63562177/mongod-aborts-on-mac](https://stackoverflow.com/questions/63562177/mongod-aborts-on-mac)
