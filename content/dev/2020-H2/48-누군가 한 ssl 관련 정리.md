---
title: "누군가 한 ssl 관련 정리"
labels: []
published: true
date: 2020-09-17T10:37:07+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 48
tistoryUrl: "https://yeolceo.tistory.com/48"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2020-09-17 10:37:07"
language: ko
bloggerPostId: "1051935676625125367"
---
[blusky10.tistory.com/352](https://blusky10.tistory.com/352)

결국 이걸로 다함 이게 짱임.

req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 3650

```html
option = {
      key: fs.readFileSync('./open_ssl/openssl-0.9.8k_X64/bin/key.pem'),
      cert: fs.readFileSync('./open_ssl/openssl-0.9.8k_X64/bin/cert.pem'),
      passphrase:'<PASSPHRASE>',
      agent:false
  };

  https.createServer(option, app).listen(sslport, () => {
      console.log(`[HTTPS] Soda Server is started on port ${sslport}`)
  });
```

react 는 처음 시작을 set HTTPS=true&&npm start 를 하면되는데

proxy에설정할때 ## 붙어있는 secure:false 를 해야한다.

target: 'https://localhost:5050/',   
changeOrigin: true,   
##secure: false

이것만하면 https는 괜찮다 . 

openssl이니까 어차피 인증서 사올꺼아니면 다의미없다.

node.js 에서는 openssl 을 받아온도 (링크)

아래와 같이 설정해주면 된다. 

HTTPS를 위해서 인증서 발급을 위해 openssl 을 이용해봤다..

[https://sourceforge.net/projects/openssl/](https://sourceforge.net/projects/openssl/)

여기 가서 다운 받아서 압축을 풀면 일단 설치는 완료된다. (윈도우 기준)

**1\. Private KEY 생성**

**명령어 : oepnssl genrsa -out \[파일명\] 2048**

**\# openssl genrsa -out private.key 2048**

Generating RSA private key, 2048 bit long modulus

.................................................+++

.................+++

e is 65537 (0x10001)

**private.****key**

\-----BEGIN RSA PRIVATE KEY-----
(removed)
-----END RSA PRIVATE KEY-----

**2\. Public Key 생성**

**명령어 : openssl rsa -in \[private key 파일명\] -pubout -out \[파일명\]**

**\# openssl rsa -in private.****key** **\-pubout -out public.****key** 

writing RSA key

**public.****key** 

\-----BEGIN PUBLIC KEY-----
(removed)
-----END PUBLIC KEY-----

**3\. CSR 생성 (Certificate Signing Request - 인증서 서명 요청)**

\- 인증서 발급을 위한 필요한 정보를 담고 있는 인증서 신청 형식 데이터 이다. 

<table style="border-collapse: collapse; width: 100%;" border="1" width="784"><tbody><tr><td rowspan="1"><p>&nbsp;구분</p></td><td rowspan="1">&nbsp;작성 예&nbsp;</td></tr><tr><td><p>&nbsp;Country Name (국가코드)&nbsp;</p></td><td><p>&nbsp;KR</p></td></tr><tr><td><p>&nbsp;State or Province Name (시/도의 전체이름)</p></td><td><p>&nbsp;Seoul</p></td></tr><tr><td><p>&nbsp;Locality Name (시/군/구 등의 이름)</p></td><td><p>&nbsp;Songpa-gu&nbsp;</p></td></tr><tr><td><p>&nbsp;Organization (회사이름)</p></td><td><p>&nbsp;XXXX</p></td></tr><tr><td><p>&nbsp;Organization Unit (부서명)</p></td><td><p>&nbsp;Server</p></td></tr><tr><td><p>&nbsp;Common Name (SSL 인증서를 설치할 서버의 Full Domain)</p></td><td><p>&nbsp;www.xxxx.com</p></td></tr></tbody></table>

**주의 사항**

**\- Common Name 에는 인증서를 설치할 사이트의 도메인의 이름을 넣어야 한다. (ip, port, http, https 포함불가능)**

**명령어 : openssl req -new -key** **\[private key 파일명\]** **-out** **\[파일명\]**

**\# openssl req -new -key private.****key** **\-out private.csr**

You are about to be asked to enter information that will be incorporated

into your certificate request.

What you are about to enter is what is called a Distinguished Name or a DN.

There are quite a few fields but you can leave some blank

For some fields there will be a default value,

If you enter '.', the field will be left blank.

\-----

Country Name (2 letter code) \[AU\]:KR

State or Province Name (full name) \[Some-State\]:Seoul

Locality Name (eg, city) \[\]:Seoul

Organization Name (eg, company) \[Internet Widgits Pty Ltd\]:local

Organizational Unit Name (eg, section) \[\]:local

Common Name (eg, YOUR name) \[\]:local

Email Address \[\]:test@test.com

Please enter the following 'extra' attributes

to be sent with your certificate request

A challenge password \[\]:test

An optional company name \[\]:test

중간중간 뭐라고 나오는 내용들이 많이 있다. 일단 테스트 이기 때문에 대충 넣었다.

**private.csr**

\-----BEGIN CERTIFICATE REQUEST-----
(removed)
-----END CERTIFICATE REQUEST-----

**4\. CRT 인증서 만들기**

**명령어 : openssl req -x509 -days \[기간\] -key** **\[private key 파일명\] -in \[csr 파일명\]** **-out** **\[파일명\] -days \[기간\]**

**\# openssl req -x509 -days 365 -key private.key -in private.csr -out mycommoncrt.crt -days 365**

You are about to be asked to enter information that will be incorporated                     

into your certificate request.                                                               

What you are about to enter is what is called a Distinguished Name or a DN.                  

There are quite a few fields but you can leave some blank                                    

For some fields there will be a default value,                                               

If you enter '.', the field will be left blank.                                              

\-----                                                                                        

Country Name (2 letter code) \[AU\]:KR                                                         

State or Province Name (full name) \[Some-State\]:Seoul                                        

Locality Name (eg, city) \[\]:Songpa-gu                                                        

Organization Name (eg, company) \[Internet Widgits Pty Ltd\]:                                  

Organizational Unit Name (eg, section) \[\]:                                                   

Common Name (eg, YOUR name) \[\]:                                                              

Email Address \[\]:                                                                            

**mycommoncrt.crt**

\-----BEGIN CERTIFICATE-----
(removed)
-----END CERTIFICATE-----

**5\. 인증서 Config 파일 (test.conf)**

\[req\]

default\_bits = 2048

prompt = no

default\_md = sha256

req\_extensions = req\_ext

distinguished\_name = dn

\[ dn \]

C\=KR

ST\=Seoul

L\=Seoul

O\=COMPANY

OU\=DEV

emailAddress\=test@test.com

CN = testmachine

\[ req\_ext \]

subjectAltName = @alt\_names

\[ alt\_names \]

IP.1 = 111.111.111.111

DNS.1 = test.com

위에서 만들다 보면 계속 같은 내용을 써야 한다. 그래서 그 부분을 파일로 만들어 놓고 csr, crt 생성할때 사용하면 된다.

**openssl req -new -key private.****key** **\-out private.csr -config test.conf**

**openssl req -x509 -days 365 -key private.key -in private.csr -out mycommoncrt.crt -days 365 -config test.conf**

그리고 이렇게 해서 인증서를 만들었을때 subjectAltName 이 안들어간다 . 그 부분이 필요할 경우에는 이렇게 명령어를 사용하면 된다. 

**openssl req -x509 -days 365 -key private.key -in private.csr -out mycommoncrt.crt -days 365 -config test.conf -extensions req\_ext**

* * *

**openssl 팁 몇가지**

**openssl x509 -text -noout -in <인증서파일>  : 인증서 내용을 볼수 있다.**

**openssl x509 -in mycommoncrt.crt -out mycommonpem.pem -outform PEM  : CRT 파일을 PEM 파일로 변환한다.**

참고자료

[https://www.comodossl.co.kr/certificate/ssl-installation-guides/Apache-csr-crt.aspx](https://www.comodossl.co.kr/certificate/ssl-installation-guides/Apache-csr-crt.aspx)

[https://www.kicassl.com/sslcert/sslcert/formSslCert.sg](https://www.kicassl.com/sslcert/sslcert/formSslCert.sg)

[http://namjackson.tistory.com/24](http://namjackson.tistory.com/24)
