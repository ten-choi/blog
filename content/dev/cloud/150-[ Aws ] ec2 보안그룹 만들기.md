---
title: "[ Aws ] ec2 보안그룹 만들기"
labels: ["Cloud","aws"]
published: false
date: 2022-12-12T18:48:27+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 150
tistoryUrl: "https://yeolceo.tistory.com/150"
tistoryCategory: "Cloud"
tistoryTags: ["aws","AWS","aws","aws"]
tistoryPostedAt: "2022-12-12 18:48:27"
language: ko
bloggerPostId: "4460745441848732029"
---
#### ? **환경** 

Aws web

#### ? **개요**

ec2 사용하면서 보안 그룹 설정을 해봅시다!

#### ? **목차**

-   보안 그룹 만들기

보안 그룹이란? Aws에서 지원하는 Ec2의 IP, Port의 인바운드, 아웃바운드 등을 설정에 사용에 제한을 줘서  
보안성을 올리는 EC2의 부속 기능입니다.

## **\- 보안 그룹 만들기**

ec2를 검색해줍니다  
카테고리에 보안 그룹을 선택합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/150/img.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/150/img_1.webp)

보안 그룹을 생성합니다.  

보안 그룹의 이름, 설명은 간단하게 작성해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/150/img_2.webp)

인바운드는 외부에서 ec2로 접속할 때 허용하는 ip와 포트입니다. http, https로 접속할 예정이기 때문에 80, 443을 설정했습니다.  
그게 아니신 분들은 유형에서 사용자 지정 TCP 등을 쓰시면 됩니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/150/img_3.webp)

안에서 밖으로 나가는 트래픽에는 제한이 없게 처리했습니다.  
보안상 별다른 제한을 걸지 않아도 되는 경우입니다.   
이또 한 마찬가지로 설정이 필요하신 분들은 특정 대상 ip, port만 아웃 바운드될 수 있도록 설정합니다.  
보안 그룹 생성 버튼을 눌러주세요.

이제 필요할 때 해당 보안 그룹을 사용할 수 있습니다.  

마지막으로 이름은 나와서 따로 설정해줘야 합니다.  
방금 만든 보안 그룹에 이름을 설정해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/150/img_4.webp)

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
