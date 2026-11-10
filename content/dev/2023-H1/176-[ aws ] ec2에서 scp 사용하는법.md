---
title: "[ aws ] ec2에서 scp 사용하는법"
labels: ["Cloud","aws","scp","EC2"]
published: true
date: 2023-06-15T18:34:46+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 176
tistoryUrl: "https://yeolceo.tistory.com/176"
tistoryCategory: "Cloud/aws"
tistoryTags: ["scp","KR","EC2","aws"]
tistoryPostedAt: "2023-06-15 18:34:46"
language: ko
bloggerPostId: "6780717336994776998"
---
scp는 secure copy protocol의 약어로 ssh접근 기반의 sftp를 해주는 수단이다  
aws에서 찾아보면 친절하게 아래와 같은 명령어로 scp를 사용하라고 나와있다   
[aws문서참조](https://docs.aws.amazon.com/ko_kr/AWSEC2/latest/UserGuide/AccessingInstancesLinux.html)

```shell
scp -i /path/key-pair-name.pem /path/my-file.txt ec2-user@instance-public-dns-name:path/
```

위의 명령어 진행하면 내 경우에는 아래와 같은 에러가 나왔다

```shell
scp: Received message too long 1349281121
scp: Ensure the remote shell produces no output for non-interactive sessions.
```

찾아본 결과 sftp인증을 시도할 때 발생하는 에러다  
scp 말고 sftp로 접속 테스트를 해보면 동일한 issue가 생긴다  
openSsh의 sftp server를 사용할 수 없거나 경로를 못 찾는 경우 혹은  
sftp가 session을 초기 생성할 때 불필요한 정보를 출력해서 문제가 되는듯하다

aws경로에서 /etc/ssh/sshd\_config를 확인해 보자  
아래 #으로 주석처리돼 있는 line이 주석 없이 존재할 것이다. 해당 부분 아래와 같이 주석처리하고  
openSsh package의 내부에 있는 sftp를 아래 codeBlock처럼 사용하자

```shell
#Subsystem      sftp    /usr/libexec/openssh/sftp-server

Subsystem sftp internal-sftp
ForceCommand internal-sftp -u 0002
```

forceCommand를 붙이는 이유는  
내경우에 Subsystem sftp internal-sftp 명령어로만 했을 경우 동일한 error가 나왔다  
다른 사람들 글에는 이걸로 해결했다는 사람이 꽤 많았다

나는 추가로 ForceCommand internal-sftp -u 0002 명령어를 사용했다  
첫 번째 code의 명령을 좀 더 강제하는 코드다. option은 umask permision 설정이다

```shell
sudo service sshd restart
```

sshd를 재실행하여 설정을 적용한다. scp를 실행할 경우 정상 동작이 일어났다  
위처럼 진행할 경우 나중에 접근할 때 sftp로만 접근가능하다. 그래서 파일을 옮겼다면 원래대로 설정을 돌려놓아야한다  
아니면 아래와같은 에러가 나오면서 이후 접근이 불가능해진다

```typescript
This service allows sftp connections only
```
