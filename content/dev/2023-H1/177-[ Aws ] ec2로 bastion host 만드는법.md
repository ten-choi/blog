---
title: "[ Aws ] ec2로 bastion host 만드는법"
labels: ["Cloud","aws","EC2","BastionHost"]
published: false
date: 2023-06-15T18:50:36+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 177
tistoryUrl: "https://yeolceo.tistory.com/177"
tistoryCategory: "Cloud/aws"
tistoryTags: ["KR","EC2","aws","BastionHost"]
tistoryPostedAt: "2023-06-15 18:50:36"
language: ko
bloggerPostId: "7071961182062745351"
---
### aws에서 bastionHost란

bastionHost란 직접 접근할 수 없는 private network의 instance에

접근하기 위해 private network와 통신할 수 있는 public network 내에 존재하는 instance다

bastionHost에서 ssh를 통해 private instance 혹은 db를 private subnet에

놓은 경우 bastionHost를 통해 외부에서 접근가능하며 이러한 절차로 인해 보안성이 올라간다

### bastionHost를 위한 instance를 생성을 하자

vpc는 미리 생성한 vpc를 지정해 주자. vpc가 없다면? [aws vpc 만드는 법](https://yeolceo.tistory.com/175)  
해당 instance에 접근하기 위해 vpc의 public subnet에 지정하고 public ip도 활성해 두자

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/177/img.webp)

접근할 때 vpc에 보안그룹의 inbound 규칙에 목록을 확인하자

규칙에서 모든 트래픽을 받아주는 규칙을 추가하거나 접속하려는 특정 ip가 있다면 지정해서 추가하자

### ec2 접근 및 ssh를 위한 pem 파일 작업

위와 같이 만들었다면 ec2를 접속해 보자. 우리는 vpc내부에 있는 private instance에 접근해야 한다

private instance를 만들어줄 때 사용한 keyPair인 pem file을 통해 ssh 접근을 한다

scp명령어를 통해 pem 파일을 업로드해 본다

내 경우에는 오른쪽 링크의 issue처리가 필요했다. 해당 글을 참고하자 -> [scp issue fix](https://yeolceo.tistory.com/176)

```shell
scp -i /path/key-pair-name.pem /path/my-file.txt ec2-user@instance-public-dns-name:path/
```

위와 같이 수정 후 scp명령어를 다시 해보자. 업로드가 완료되었다

private instance의 ip를 통해 pem과 함께 ssh 로그인을 진행하자

```shell
ssh -i /path/key-pair-name.pem instance-user-name@instance-public-dns-name
```

scp 할 때까지는 난 전부 root user의 권한을 사용했다

하지만 private instance에 접근할 때는 ec2-user로 접근해야 한다

권한 때문인지 root로는 접근 못하게 해 놨다 

```routeros
Warning: Permanently added '10.0.142.98' (ED25519) to the list of known hosts.
Please login as the user "ec2-user" rather than the user "root".
```

pem file도 ec2-user에서 사용하기 위해 권한을 변경하자

```shell
chmod 755 <keyPair file>
```

그리고 private instance의 ec2에 다시 접근해 보자

로그인이 성공적으로 되었다면 해당작업은 마무리가 된다

### 마지막 간단 순서 정리

터미널에서 pem파일 기반 ssh를 통해 ec2 instance에 접근합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/177/img_1.webp)

아래와 같이 접근이 완료가 돼야 합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/177/img_2.webp)

사전에 pem 파일을 옮겨둔 usr/pem 위치로 이동합니다

한 번 더 pem 파일기반 ssh 접근을 시도합니다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/177/img_3.webp)

접근이 잘되면 절차가 마무리됩니다
