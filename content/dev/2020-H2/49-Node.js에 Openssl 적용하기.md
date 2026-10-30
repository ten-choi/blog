---
title: "Node.js에 Openssl 적용하기"
labels: ["ETC","SSL","OpenSSL","node.js"]
published: true
date: 2020-09-24T18:15:50+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 49
tistoryUrl: "https://yeolceo.tistory.com/49"
tistoryCategory: "ETC/SSL"
tistoryTags: ["OpenSSL","openssl","node.js"]
tistoryPostedAt: "2020-09-24 18:15:50"
language: ko
bloggerPostId: "6792058715713319792"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/49/img.webp)

## Openssl 이란

네트워크를 통한 데이터 통신을 할 때 쓰이는 프로토콜인 TLS와 SSL을 오픈소스로 해놓은 것입니다.

SSL은 보안 소켓 계층이란 뜻으로 Secure Sockets Layer의 약자입니다. 

풀어서 말씀드리면 웹사이트나 서버 사이에 전송되는 데이터들을 암호화해주는 기술입니다.

TLS는  전송 계층 보안이란 뜻으로 Transport Layer Security의 약자입니다.

최신 기술의 ssl로 보다 강력한 버전의 인증서입니다. 

결론적으로 웹에서 통신간에 데이터를 암호화해주는 기술입니다. 

## Openssl 만들기 위한 툴 다운

먼저 하단의 링크를 사용하여 ssl을 만들기 위한 툴을 다운로드합니다. 

[sourceforge.net/projects/openssl/](https://sourceforge.net/projects/openssl/)

다운로드를 하고 압축을 풀어주시면 아래와 같은 화면이 나옵니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/49/img_1.webp)

url에 맞춰 폴더를 찾아보시면 openssl.exe라는 파일이 보일 것입니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/49/img_2.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/49/img_3.webp)

자 실행을 완료하였다면 여러분도 위와 같은 명령 프롬프트와 같은 창이 나왔을 것입니다. 

## Openssl 만들기

req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650

위와 같은 코드를 입력하면 10년짜리 인증서가 나옵니다. -> 이름을 적는 부분이나 비밀번호는 알아서 합니다.

(코드에 대한 해석은 좀 더 공부하고 수정하겠습니다.)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/49/img_4.webp)

위와 같이 key.pem, cert.pem 같은 2가지 파일이 나옵니다. 이 파일들을 이제 

node.js 에 서버로 가져갑시다. (node.js의 서버를 실행하기 어려우시다면 하단의 링크를 참조하세요)

[yeolceo.tistory.com/29](https://yeolceo.tistory.com/29)

기존의 express나 koa로 http 서버를 실행하셨다면

```html
option = {
      key: fs.readFileSync('./open_ssl/openssl-0.9.8k_X64/bin/key.pem'),
      cert: fs.readFileSync('./open_ssl/openssl-0.9.8k_X64/bin/cert.pem'),
      //경로는 본인꺼에 맞게 설정합시다. 
      passphrase:'여기에 비번넣으세요',
      agent:false
  };

// app 은 이미 express 나 koa로 app.listen 이 가능한상태여야 합니다. 

  https.createServer(option, app).listen(5050, () => {
      console.log(`[HTTPS] Soda Server is started on port ${5050}`)
  });
```

그대로 명령 프롬프트에서 실행해주시면 됩니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/49/img_5.webp)

그러면 https에서 node.js가 실행이 될 것입니다. 

공인 인증된 ssl이 아니므로 당연히 안전하지 않음이나 주의 상태로 실행됩니다. 

지적은 언제나 감사히 받습니다. 감사합니다.
