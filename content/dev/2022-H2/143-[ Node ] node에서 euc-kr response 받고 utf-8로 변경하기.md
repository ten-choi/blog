---
title: "[ Node ] node에서 euc-kr response 받고 utf-8로 변경하기"
labels: ["TS","JS","nodejs","node"]
published: false
date: 2022-08-22T16:56:07+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 143
tistoryUrl: "https://yeolceo.tistory.com/143"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["node","node","node"]
tistoryPostedAt: "2022-08-22 16:56:07"
language: ko
bloggerPostId: "1815563426219844719"
---
#### ? **환경** 

Mac M1  
Node 16  
VsCode

#### ? **개요**

Node에서 axios를 사용할 때 response값이 euc-kr일 경우 utf-8로 바꾸기!

#### ? **목차**

-   decode 할 소스 만들기
-   결과 확인하기

## **\-  decode 할 소스 만들기**

필요한 lib를 추가해줍시다. restApi와 decode를 위한 lib입니다.

```typescript
npm install express --save
npm install axios --save
npm install iconv-lite --save
```

node 환경에서 axios를 request 할 수 있는 상황을 만들어줍니다. 

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
      return result;
    })
    .catch((err: any) => {
      console.log(err);
      return err;
    });
```

## **\-  결과 확인하기**

해당 소스를 postman으로 실행하거나 서버 구조 없이 함수로 실행하면 결괏값을 알 수 있습니다.

설명을 추가하자면 돌아오는 값이 euc-kr일 경우 responseType을 arraybuffer로 꼭 받아줘야 합니다.  
위의 이유를 설명드리자면 response를 받을 때  
responseType에 대한 기본값이 있는듯합니다. 그래서 들어오는 euc-kr 값을 내부적으로  
설정된 기본 타입으로 받기 때문에 데이터가 깨지게 됩니다.   
그 데이터를 response에서 받고 iconv로 디코딩하면 문제가 됩니다.  
arraybuffer로 받는 타입을 지정해줘야 깨지지 않은 온전한 값을 이용해 iconv로 디코딩 가능합니다.

pg사때문에 euc-kr 디코딩하는 사람 꽤 있는 거 같아요~

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
