---
title: "[ Ngrok ] Localhost를 외부에서 접속하기위한 Service"
labels: ["ThirdParty","ETC","ngrok"]
published: true
date: 2023-08-03T13:50:20+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 184
tistoryUrl: "https://yeolceo.tistory.com/184"
tistoryCategory: "ThirdParty/ETC"
tistoryTags: ["KR","ngrok"]
tistoryPostedAt: "2023-08-03 13:50:20"
language: ko
bloggerPostId: "8092792576624962973"
---
#### Environment

-   mac

### Ngrok 이란?

**localhost를 외부에서 접속**할 수 있게 domain을 연결해 주는 **service**이다

무료 plan만 사용해도 충분히 쓸만하다. [downloadLink](https://ngrok.com/download) 필요하다면 바로 다운로드해 보자

### 사용법

아래 명령어 같은 cli로 실행할 수 있다

```angelscript
ngrok http 8000
```

본인이 실행한 서버가 **8000**일 경우 실행한 server에 대해 외부에서 접근가능한 **https domain**이 나온다

위의 domain을 사용하면 localhost에서 받을 수 없는 **thirdParty의 callBack api** 등을 받거나

front에서 테스팅 중에 **화면공유가 필요하지만 서버가 따로 없는 경우라면**?

**ngrok을 통해 접근**하는 식으로 사용해도 괜찮을듯하다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/184/img.webp)

위처럼 실행해 준 후 **forwarding url**을 외부에 넘겨주거나 내가 사용하면 된다

은근 사용처가 많아서 기억해 놓으면 좋다
