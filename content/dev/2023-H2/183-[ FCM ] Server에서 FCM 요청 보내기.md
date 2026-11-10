---
title: "[ FCM ] Server에서 FCM 요청 보내기"
labels: ["ThirdParty","FCM","Push"]
published: true
date: 2023-07-26T11:09:32+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 183
tistoryUrl: "https://yeolceo.tistory.com/183"
tistoryCategory: "ThirdParty/FCM"
tistoryTags: ["KR","FCM","Push"]
tistoryPostedAt: "2023-07-26 11:09:32"
language: ko
bloggerPostId: "3449118686883166250"
---
#### Environment

-   mac
-   node 18

### FCM이란

Firebase Cloud Messaging의 약어로, google에서 **어느 정도 무료**로 제공하는 **pushNotification service**다. 많이 쓰면 과금이다

### FCM 사용에 필요한 key 발급

**앱 쪽 토큰**은 이미 발급돼 있다고 가정하자. 프로젝트 설정에서 key를 찾으러 가야 한다

오른쪽 구석의 **계정권한관리** 버튼을 클릭하자

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/183/img.webp)

아래의 화면처럼 넘어간다. 왼쪽 카테고리의 서비스 계정을 선택한다

그리고 오른쪽에 보면 **키관리**가 있다. 이곳을 클릭해서 키추가를 하면 사용할 **json 값**을 얻을 수 있다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/183/img_1.webp)

### backendSource작업

위에서 얻은 json파일에서 **projectId, clientEmail, privateKey** 이렇게 3개를 사용한다

env에 해당값들 정리해서 넣어준다. config에 따로 선언하고 호출해서 사용하면 된다

```typescript
const fcm_config = {
  projectId: process.env.FCM_PROJECT_ID,
  clientEmail: process.env.FCM_CLIENT_EMAIL,
  privateKey: process.env.FCM_PRIVATE_KEY,
};
```

아래처럼 fcm을 보낼 api를 만들어주자. 잘 모르겠으면 [공식문서](https://firebase.google.com/docs/cloud-messaging/concept-options?hl=ko)를 참고하자

아래와 같이 코드를 작성 후 testing 하면 token을 발급한 app을 가진 스마트폰에 **push notification이 전송**된다

```typescript
import * as admin from 'firebase-admin'; //firebase 선언
import { fcmConfig } from '~v3/core/config/fcm'; //config invoke

   admin.initializeApp({
      credential: admin.credential.cert(fcm_config),
    });

    const fcm_message = admin
      .messaging()
      .send({
        token, //모바일 기기에서 발급한 token-> 보내는곳
        // topic: '', // 전체 유저에게 보내고싶을때 사용
        apns: {
          headers: {
            'apns-push-type': 'alert',
            'apns-priority': '5',
          },
          payload: {
            aps: {
              alert: {
                title: 'iOS title',
                body: 'iOS body',
              },
              sound: 'default',
              contentAvailable: true, //data-only일경우 true로 해야 알림받기 가능
            },
          },
        },
        android: {
          priority: 'high', //data-only일경우 high로 해야 알림받기 가능
          notification: {
            title: 'Android title',
            body: 'Android body',
            channelId: 'test_test123', // 클라이언트에서 만든 채널
          },
        },
      })
      .then((data) => {
        return data;
      })
      .catch((err) => {
        console.error(err);
        throw new Error(err);
      });
```
