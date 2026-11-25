---
title: "How to Use WebSocket in Node.js"
labels: ["TS","JS","nodejs","WebSocket","node","Archive"]
published: true
date: 2021-10-18T18:03:11+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 105
tistoryUrl: "https://yeolceo.tistory.com/105"
tistoryCategory: "TS, JS/nodejs"
tistoryTags: ["WebSocket","node","node.js"]
tistoryPostedAt: "2021-10-18 18:03:11"
language: en
bloggerPostId: "8852408462682400881"
---
## \-What Is WebSocket

How to use WebSocket in Node.js.

wss stands for web socket server, and ws stands for web socket.

You can think of wss as a server URL where the connection, unlike a REST API call, stays open all the time.

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
