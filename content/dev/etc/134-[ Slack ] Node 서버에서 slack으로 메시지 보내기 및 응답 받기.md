---
title: "[ \bSlack ] \bNode 서버에서 slack으로 메시지 보내기 및 응답 받기"
labels: ["ThirdParty","Slack","node"]
published: false
date: 2022-06-10T15:14:51+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 134
tistoryUrl: "https://yeolceo.tistory.com/134"
tistoryCategory: "ThirdParty/Slack"
tistoryTags: ["slack","slack","Slack","node"]
tistoryPostedAt: "2022-06-10 15:14:51"
language: ko
bloggerPostId: "6424180471742320734"
---
#### 환경

NodeJS 16v  
koa

#### 개요

node 서버에서 slack으로 메시지를 보내면 버튼을 통해 예, 아니오 등 버튼에 post API URL을 등록해놓고 서버에서 hook으로 받아줍시다.

환경은 node와 slack 이기 때문에 두 가지다 설치돼있다는 가정으로 진행합니다. 라이브러리는 koa로 하지만 express랑 거의 차이 없으니까 편하게 진행하세요

#### 목차

-   Slack 이란
-   node 서버 세팅 1
-   Slack 환경설정
-   node 서버 세팅 2
-   Slack 메시지 버튼을 통해 hook 서버로 데이터 넘겨주기

## **\- Slack 이란**

클라우드 기반 팀 협업 도구라고 합니다. PC카카오 확장판이라고 생각하시면 편합니다. 일할 때 메시지도 보내고 일정도 조율하고 파일도 보내고 그런 메신저 응용프로그램입니다. 개인적 인용 도인 카카오톡과 구분 짓는 것도 포함하여 여러 이유로 사내 메신저를 사용하는 경우가 많습니다.

## **\- node 서버 세팅 1**

slack메시지에 API를 쏴주기 위해 axios를 import 해줍니다. object 형식은 [링크](https://api.slack.com/legacy/outmoded-messaging)에 따른 slack에서 요청하는 형식에 맞춰줍니다. 

변수 중에 url과 auth는 진행하면서 추가적으로 수정하겠습니다.

```bash
import axios from 'axios';

export default async (ctx: any) => {

  const data: object = {
    channel: 'test',  

    attachments: [
      {
        title: `test title `,
        text: `메세지 보내기 ~`,
      },
    ],
  };

  const config: object = {
    method: 'post',
    url:  '',
    headers: {
      'Content-Type': 'application/json',
      Authorization: '' 
    },
    data,
  };

  const result = await axios(config)
    .then((data: any) => {
      console.log(data);
    })
    .catch((err: any) => {
      console.error(err);
    });

  return (ctx.body = result);
};
```

## **\- Slack 환경설정**

슬랙을 설치했고 실행하는 환경까지 갖췄다면 우선 새 워크스페이스를 테스트 용도로 만들어줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img.webp)

그리고 채널에 본인이 원하는 채널 추가 버튼을 눌러 원하는 채널명을 설정하고 채널을 생성해줍니다. 

저희가 api를 쏴줄 채널명이기 때문에 영어로 지어줍니다. 

그리고 [**Slack**](https://api.slack.com/) 사이트를 접속해줍니다. 그다음 로그인을 하고 밑줄 그어놓은 Your apps를 클릭해줍니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_1.webp)

아래와 같은 페이지로 넘어가면 새로운 앱을 만들어줍니다. 저희가 slack을 사용하기 위한 앱을 만들어준다고 생각하세요!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_2.webp)

저는 명칭을 yeoltest로 지었습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_3.webp)

왼쪽 카테고리를 따라가다 보면 OAuth라는 인증과 권한, 토큰 발급을 위한 카테고리가 있습니다. 해당 카테고리에서 토큰을 받아줍시다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_4.webp)

그리고 해당 토큰의 권한을 설정할 때 아래와 같이 Scops에서 chat:write.public를 추가합니다. 나머지 추가된 건 신경 안 쓰셔도 됩니다. 

해당 토큰이 chat 권한이 있을 때 slack 채널에 채팅이 가능합니다!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_5.webp)

필요한 환경설정이 완료되었습니다. node 소스를 수정해 api를 날려봅시다.

## **\- node 서버 세팅 2**

이전 서버 세팅 1에서 모자라거나 없던 부분을 아래의 블록을 보고 채워줍시다.

```bash
export default async (ctx: any) => {
  const ctxBody: object = ctx.request.body;

  const data: object = {
    channel: 'test',

    attachments: [
      {
        title: `test1`,
        text: `가즈아ㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏ:  `,

      },
    ],
  };

  const config: object = {
    method: 'post',
    url: 'https://slack.com/api/chat.postMessage',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer xoxb-364당신의토큰`, 
    },
    data,
  };

  const result = await axios(config)
    .then((data: any) => {
      console.log(data);
    })
    .catch((err: any) => {
      console.error(err);
    });

  return (ctx.body = result);
};
```

그리고 request를 보낸다면 slack 채널에 메시지가 나옵니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_6.webp)

축하드립니다! 벌써 기본적인 메시징을 구현했습니다.

## **\- Slack 메시지 버튼을 통해 hook 서버로 데이터 넘겨주기**

여기까지 하면 깔끔하게 기능 사용 가능합니다. 예를 들어 실제로 서비스하고 있는 플랫폼이라면 CS팀에서 판단하고 처리할 형식을 만들어야 할 수도 있습니다.

토큰을 발급했던 사이트의 왼쪽의 카테고리에 interactivity&shortcuts을 클릭해줍니다. slack에서 버튼 푸시를 통해 post api 날려줄 때는 url을 이곳에 미리 등록해주고 callback ID를 통해 호출합니다. 다른 메시징 시스템도 비슷하게 처리합니다.

그럼 아래 이미지를 참조하여 하나 만들어주세요 저는 아래와 같이 심플하게 하나 만들었습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_7.webp)

위와 같이 hook으로 받아줄 url을 설정했습니다. 기존 소스와 크게 다를 것 없이 아래의 변경사항만 추가해주세요 (ex. callback\_id

```bash
const data: object = {
    channel: 'test', 

    attachments: [
      {
        title: `test1`,
        text: `가즈아ㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏㅏ:  `,
        color: '#2980B9',
        callback_id: 'yeol_action',
        attachment_type: 'default',
        actions: [
          {
            name: 'buttonName',
            text: 'text~~~',
            type: 'button',
            value: `원하는 값`,
          },
        ],
      },
    ],
  };
```

버튼을 2개로 세팅하고 예 아니 오를 하거나 필요한 값을 받는 것도 가능합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/134/img_8.webp)

위처럼 잘 실행되었다면 축하드립니다! auth 토큰 없이 slack 메시징을 사용하고 싶다면 카테고리의 incoming webhook을 사용해주세요  url 만으로도 slack에 메시지를 날릴 수 있습니다. 

성실한 코딩 하세요!
