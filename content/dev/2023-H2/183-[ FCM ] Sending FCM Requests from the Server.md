---
title: "[ FCM ] Sending FCM Requests from the Server"
labels: ["ThirdParty","FCM","Push","Archive"]
published: true
date: 2023-07-26T11:09:32+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 183
tistoryUrl: "https://yeolceo.tistory.com/183"
tistoryCategory: "ThirdParty/FCM"
tistoryTags: ["KR","FCM","Push"]
tistoryPostedAt: "2023-07-26 11:09:32"
language: en
bloggerPostId: "3449118686883166250"
---
#### Environment

-   mac
-   node 18

### What Is FCM?

FCM stands for Firebase Cloud Messaging. It's a **push notification service** from Google that's **free up to a point**. Use it heavily and you'll get billed.

### Getting the Key You Need for FCM

Let's assume the **app-side token** has already been issued. We need to go find the key in the project settings.

Click the **Manage account permissions** button in the corner on the right.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/183/img.webp)

You'll land on a screen like the one below. Pick Service accounts from the categories on the left.

On the right you'll see **Manage keys**. Click it and add a key, and you'll get the **JSON** you need.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/183/img_1.webp)

### Backend Source

From the JSON file above, we use three values: **projectId, clientEmail, and privateKey**.

Put those values in your env. Then declare them in a separate config and import it where you need it.

```typescript
const fcm_config = {
  projectId: process.env.FCM_PROJECT_ID,
  clientEmail: process.env.FCM_CLIENT_EMAIL,
  privateKey: process.env.FCM_PRIVATE_KEY,
};
```

Now let's write an API that sends the FCM message, like the one below. If anything's unclear, check the [official docs](https://firebase.google.com/docs/cloud-messaging/concept-options?hl=ko).

Write the code below and test it, and a **push notification gets delivered** to the phone running the app that issued the token.

```typescript
import * as admin from 'firebase-admin'; // firebase import
import { fcmConfig } from '~v3/core/config/fcm'; // config invoke

   admin.initializeApp({
      credential: admin.credential.cert(fcm_config),
    });

    const fcm_message = admin
      .messaging()
      .send({
        token, // token issued by the mobile device -> the recipient
        // topic: '', // use this when you want to send to all users
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
              contentAvailable: true, // must be true for data-only messages to be received
            },
          },
        },
        android: {
          priority: 'high', // must be high for data-only messages to be received
          notification: {
            title: 'Android title',
            body: 'Android body',
            channelId: 'test_test123', // channel created on the client
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
