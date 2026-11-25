---
title: "[ Mac ] ProxyCommand"
labels: ["OS","Mac","proxycommand","Archive"]
published: true
date: 2023-08-10T17:44:01+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 186
tistoryUrl: "https://yeolceo.tistory.com/186"
tistoryCategory: "OS/Mac"
tistoryTags: ["KR","proxycommand"]
tistoryPostedAt: "2023-08-10 17:44:01"
language: en
bloggerPostId: "691138322332413031"
---
From the ~ directory on a Mac,

open ~/.ssh/config:

```bash
ui-MacBookPro ~ % vi .ssh/config
```

Define proxy-server as the server to hop through,

then enter the IP of the server you actually want to connect to.

```bash
# The server to hop through
Host proxy-server
HostName 13.125.123.123 # host of the proxy server
User ec2-user # we log in as ec2-user, so that's the User
IdentityFile ~/.ssh/Key.pem

# The server you actually want to connect to
Host dev-server
HostName 10.1.123.123
User ec2-user
IdentityFile ~/.ssh/Key.pem
ProxyJump proxy-server
```

ProxyCommand is one of the options in the SSH client config. It routes an SSH connection through a specific proxy server: the SSH client first connects to the proxy server, and then connects to the remote host through it.

```
# The server to hop through
Host proxy-server
HostName 13.125.123.123 # host of the proxy server
User ec2-user # we log in as ec2-user, so that's the User
IdentityFile ~/.ssh/Key.pem

# The server you actually want to connect to
Host dev-server
HostName 10.1.123.123
User ec2-user
IdentityFile ~/.ssh/Key.pem
ProxyJump proxy-server
```
