---
title: "[ Mac ] proxycommand"
labels: ["OS","Mac","proxycommand"]
published: false
date: 2023-08-10T17:44:01+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 186
tistoryUrl: "https://yeolceo.tistory.com/186"
tistoryCategory: "OS/Mac"
tistoryTags: ["KR","proxycommand"]
tistoryPostedAt: "2023-08-10 17:44:01"
language: ko
bloggerPostId: "691138322332413031"
---
mac의 ~ dirictory에서

~.ssh/config  로 접근한다

```typescript
ui-MacBookPro ~ % vi .ssh/config
```

proxy-server를 설정해서 거쳐갈서버를 설정하고

본래접속할 서버의 ip 를 입력하여 

```typescript
#거쳐가는 서버
Host proxy-server
HostName 13.125.123.123 #proxy서버의 host
User ec2-user #ec2-user에 접근하기때문에 use로 표기
IdentityFile ~/.ssh/Key.pem

# 본래 접속할 서버
Host dev-server
HostName 10.1.123.123
User ec2-user
IdentityFile ~/.ssh/Key.pem
ProxyJump proxy-server
```

ProxyCommand는 SSH 클라이언트 설정에서 사용되는 옵션 중 하나로, SSH 연결을 특정 프록시 서버를 통해 전달하는 데 사용됩니다. 이를 통해 SSH 클라이언트는 먼저 프록시 서버에 연결한 다음, 프록시 서버를 통해 원격 호스트에 연결하게 됩니다.

```
#거쳐가는 서버
Host proxy-server
HostName 13.125.123.123 #proxy서버의 host
User ec2-user #ec2-user에 접근하기때문에 use로 표기
IdentityFile ~/.ssh/Key.pem

# 본래 접속할 서버
Host dev-server
HostName 10.1.123.123
User ec2-user
IdentityFile ~/.ssh/Key.pem
ProxyJump proxy-server
```
