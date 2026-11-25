---
title: "[ Node ] Receiving an EUC-KR Response in Node and Converting It to UTF-8"
labels: ["TS","JS","nodejs","node","Archive"]
published: true
date: 2022-08-22T16:56:07+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 143
tistoryUrl: "https://yeolceo.tistory.com/143"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["node","node","node"]
tistoryPostedAt: "2022-08-22 16:56:07"
language: en
bloggerPostId: "1815563426219844719"
---
#### ? **Environment**

Mac M1  
Node 16  
VsCode

#### ? **Overview**

When using axios in Node, converting the response to UTF-8 if it comes back as EUC-KR!

#### ? **Contents**

-   Writing the decoding code
-   Checking the result

## **\-  Writing the Decoding Code**

Let's add the libraries we need: one for the REST API and one for decoding.

```typescript
npm install express --save
npm install axios --save
npm install iconv-lite --save
```

Set up a situation where you can make an axios request in a Node environment.

```
const config: object = {
    method: 'post',
    url,
    headers: {
      'Content-Type': 'application/json',
    },
    params: data,
    responseType: 'arraybuffer',
  };

  const result = await axios(config)
    .then(async (res: any) => {
      const resData = iconv.decode(res.data, 'euc-kr');
      console.log(resData);
      return resData;
    })
    .catch((err: any) => {
      console.log(err);
      return err;
    });
```

## **\-  Checking the Result**

Run this code through Postman, or just call it as a function without any server setup, and you'll see the result.

One more thing: if the returned value is EUC-KR, you must set responseType to arraybuffer.  
Here's why: when receiving a response,  
there seems to be a default responseType. So the incoming EUC-KR data gets read internally  
as that default type, and the data gets garbled.  
If you then take that data from the response and decode it with iconv, you run into problems.  
You have to specify arraybuffer as the response type so you can decode the intact, ungarbled value with iconv.

Seems like quite a few people end up decoding EUC-KR because of payment gateways (PG)~

**? Well-grounded advice is always welcome. Happy coding, and keep at it.**
