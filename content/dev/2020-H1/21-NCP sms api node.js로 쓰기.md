---
title: "NCP sms api node.js로 쓰기"
labels: ["TS","JS","nodejs","sms","naver","sens"]
published: true
date: 2020-06-11T12:46:26+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 21
tistoryUrl: "https://yeolceo.tistory.com/21"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["sms","naver","naver","sens"]
tistoryPostedAt: "2020-06-11 12:46:26"
language: ko
bloggerPostId: "6036625967639913154"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img.webp)

**naver의 50건 무료 sms api 기능을 사용하기 위한 페이지입니다. 코드를 분할하여 놓은 부분 양해 바랍니다.**

에디터는 아톰을 사용했습니다. 

일단 node.js 파일을 만들어줍시다. 

npm init을 하시고 json파일 수정하신 다음에 npm install 해주시면 기본 구성이 완료됩니다.

저는 app.js 파일을 만들어서 실행하겠습니다.

경로는 편하게 잡으시면 됩니다.

이것만 하더라도 node app을 실행하실 수 있습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img_1.webp)

```html
const express = require('express');

const app = express(); 
const crypto = require('crypto');  //암호화를 위해 사용해줍니다. sms api 사용할때 조건에도 이거쓰라고있습니다.
const request = require('request'); 
const app = express(); // 
const PORT = 3000 ; 

app.listen(PORT, ()=>{console.log('http://localhost:3000/m gonna be your localhost')}  );
```

암호화 부분은 이해가 어려울 수 있으니 일단 빼둡시다.

require 부분과 listen 사이에 get방식으로 코드를 만듭니다. 

왜냐하면 웹 주소창에서 호출할 예정이기 때문입니다. 주소는 기본 주소창에 message의 약자 m을 사용했습니다.

```html
app.get('/m', (req, res)=>{    // we use localhost3000/m 
	 const phone = '01088889999'; // 전화 받는사람
	 const accessKey = 'access key';		엑세스키 
     const secretKey = 'secret key';        씨크릿키 
     const serviceID = '서비스 아이디'     서비스아이디 넣어야할부분
     const myphone = '01012314564'; //    본인 등록의 전화번호
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img_2.webp)

서비스 아이디는 여기에 있습니다. 오른쪽에 키 부분을 클릭하시면 시크릿 말고 id 값있는 걸 가지고 옵시다.

그리고 api를 호출하기 위한 값을 설정하겠습니다.

[https://apidocs.ncloud.com/ko/common/ncpapi/#API-%ED%98%B8%EC%B6%9C%ED%95%98%EA%B8%B0](https://apidocs.ncloud.com/ko/common/ncpapi/#API-%ED%98%B8%EC%B6%9C%ED%95%98%EA%B8%B0)

다들 이거 보고 한다는데 저는 사람들 한거 보고 이거보고 완성부터 한 다음 이해했습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img_3.webp)

저기 사이트 들어가시면 인증키 이렇게 생성하라고 나옵니다. 

로그인하신 후에 마이페이지에서 인증키 관리 들어가시면 만드실 수 있습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img_4.webp)

액세스 키와 시크릿키는 요기서 받습니다. 

이렇게 프로젝트의 id와 계정의 api 인증을 해야만 sms api를 사용할 수 있습니다.

[https://docs.ncloud.com/ko/sens/sens-1-3.html](https://docs.ncloud.com/ko/sens/sens-1-3.html)

sms 프로젝트를 등록하고 본인 전화번호를 등록해야 사용 가능합니다. 여기까지는 네이버의 설명도 친절합니다.

그럼 위의 코드에 등록한 번호를 적으시면 인증을 위한 기본 설정이 끝납니다.

이제 시그니쳐 부분입니다. 여기부터 naver의 설명을 자세하게 봐야 했습니다.

```html
const space = " ";          	 // one space
     const newLine = "\n";           // new line
     const method = "POST";          // method

     const url = `https://sens.apigw.ntruss.com/sms/v2/services/${serviceID}/messages`;

	 // url (include query string) 시그니처 만들때 더해줍니다. 
     const urlsub = `/sms/v2/services/${serviceID}/messages`;

     const timestamp = Date.now().toString();   // 시간차가 많이 나면 작동안된다고 써있습니다.
     												//그래서 시간값도 넣어줍니다.

     let hmac=crypto.createHmac('sha256',secretKey);
	 let mes = [];    //배열을 만들어줍니다. 인증서는 그냥 했지만 이렇게 하면 보기 편합니다.
     //message 의 약자입니다. 경로설정할때와같이 의미있게 써줍시다.
     mes.push(method);
     mes.push(space);
     mes.push(urlsub);
     mes.push(newLine);
     mes.push(timestamp);
     mes.push(newLine);
     mes.push(accessKey);
     const signature = hmac.update(mes.join('')).digest('base64');
     //update는 mes 값을 hmac으로 설정한 크립토(암호화)함수에 대입해주는것입니다. 
     //join 으로 해주면 배열의 값을 구분해주는데 파라미터값이 존재한다면 배열 사이사이에
     // 파라미터값을 넣어줍니다.
```

[https://apidocs.ncloud.com/ko/common/ncpapi/migration\_server/](https://apidocs.ncloud.com/ko/common/ncpapi/migration_server/)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img_5.webp)

시그니쳐를 생성하는 방법 설명해보면 띄어쓰기와 라인 변경도 다 정해져 있습니다. 

naver sms api에서는 시그니쳐와 request를 이용한 api 사용 이렇게 2가지로 구분해주시면 편합니다.

**축하드립니다. 얼마 남지 않았고 이제 거의 다 왔습니다.**

시그니쳐를 완성하였으니 이제 호출 준비를 해줍니다.

[https://apidocs.ncloud.com/ko/ai-application-service/sens/sms\_v2/](https://apidocs.ncloud.com/ko/ai-application-service/sens/sms_v2/)

여기가 sms를 보내기 위한 api 부분입니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/21/img_6.webp)

그림 보시면 나와있습니다. 이렇게 하라고 따라가 봅시다.

하지만 저는 완성된 후 보면서 이해하는 과정을 거쳤기 때문에 아래의 완성 구조를 먼저 보시는 걸 추천합니다.

```html
// 저희는 경로 설정을 완료했으니 request로 요청합시다.

    request({
         method: method,    //post 로 설정을 해줬습니다. 위에서
         json: true,   	//json 을 true 로 해줘야 header 값이 제이슨값
         uri: url,  //경로 파라미터를 여기다 넣어줍니다. 
         headers: {
             'Content-Type': 'application/json; charset=utf-8',
             'x-ncp-iam-access-key' : accessKey,         //요기
             'x-ncp-apigw-timestamp': timestamp,
             'x-ncp-apigw-signature-v2': signature.toString()
         },
         body: {
             "type":"SMS",
             "contentType":"COMM",
             "countryCode":"82",
             "from": myPhoneNumber,
             "content":`code service ${인증번호를 원한다면} 입니다.`,        //요기
             "messages":[
                 {
                     "to":`${phone}`,          //요기
                 }
             ]
         }
     },function (err, res, html) {
         if(err) console.log(err);
         console.log(html);
     });
 });
```

어떻게 사용하라는 명시가 각각 있습니다. 잘 확인해가면서 진행해주세요.

자 이제 코드가 완성됐습니다. cmd에서 해당 경로의 node를 실행합니다.

주소창에서 [http://localhost:3000/m](http://localhost:3000/)을 실행해줍니다.  

핸드폰 등록 및 코딩이 잘됬다면 멋지게 핸드폰에 본인이 보낸 sms 메시지가 도착할 것입니다. 감사합니다.
