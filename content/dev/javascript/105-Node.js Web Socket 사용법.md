---
title: "Node.js Web Socket 사용법"
labels: ["TS","JS","nodejs","WebSocket","node"]
published: false
date: 2021-10-18T18:03:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 105
tistoryUrl: "https://yeolceo.tistory.com/105"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["WebSocket","node","node.js"]
tistoryPostedAt: "2021-10-18 18:03:11"
language: ko
bloggerPostId: "8852408462682400881"
---
## \-WebSocket 이란

node.js 에서 websocket 사용하는법

wss는 web socket server 를 뜻하며 ws는 web socket을 뜻함.

형식은 wss는 rest API 가 상시 유지되는 상태의 url 서버로 보시면됩니다.

```html
var WebSocketServer = require('ws').Server;

var wss = new WebSocketServer({port: 3100});

wss.on('connection', (ws) => {
  ws.on('message', (message) => {
      let sendData = {event: 'res', data: null};
      message = JSON.parse(message);
      switch (message.event) {
          case 'open':
              console.log("Received: %s", message.event);
              break;
          case 'close':
              console.log("Received: %s", message.event);
              break;
          case "req":
              sendData.data = message.data;
              ws.send(JSON.stringify(sendData));
              break;
          default:
      }
  });

  ws.on("close", async (message) => {

   console.log("close")
   console.log(message);

  });

});
```

```html
asfsadf
```
