---
title: "실행부터 해보는 AWS EC2 사용해보기"
labels: ["Cloud","AWS"]
published: true
date: 2021-02-17T18:13:15+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 87
tistoryUrl: "https://yeolceo.tistory.com/87"
tistoryCategory: "Cloud"
tistoryTags: ["AWS","aws","aws"]
tistoryPostedAt: "2021-02-17 18:13:15"
language: ko
bloggerPostId: "452258267239676622"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/aws.webp)

### **\-다하는 AWS 나도 해보기**

**aws**를 먼저 검색해서 접속해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img.webp)

회원가입을 진행해주세요. 

**aws**는 **유료 서비스**이기에 **체크카드 or 신용카드** 등 등록할 카드가 필요합니다.

그리고 저희는 **프리티어 무료 서비스**를 활용할 계획입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_1.webp)

계정을 만들면 **활성화 문제**로 약간의 시간이 필요합니다!

아래 이미지 오른쪽에 **빨간 줄** 보이시나요? **지역 선택 서울로 미리 해주세요**.

(잘 모르는 지역에 만들어놓고 리소스를 계속 사용하다 무심코 서울 지역으로 바꾸고 또 만들어서 쓰다 보면 문제가 일어날 수도 있어요..)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_2.webp)

**아시아 태평양 (서울)을** 선택해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_3.webp)

그리고 서비스를 선택해서 컴퓨팅란에 **EC2를** 선택해줍니다.

(**Elastic Computing** => 사용 가능한 자원을 탄력적으로 늘릴 수 있는 컴퓨팅)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_4.webp)

처음에 대시보드를 보면 아래와 같은 화면이 나오는데 맨 아래의 **인스턴스 시작**을 눌러주세요 저는 하나를 쓰고 있어서 

인스턴스 하나가 실행 중입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_5.webp)

저희는 **우분투 18 LTS** 버전으로 서버를 실행할 것입니다. 붉은 밑줄의 선택을 눌러주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_6.webp)

프리티어여서 CPU -> 1, 메모리 -> 1 이지만 그렇게 체감되지 않습니다. 배움에 목적을 두고 프리티어 버전을 선택하고 **검토 및 시작**을 눌러줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_7.webp)

기본 옵션 그대로 **시작하기**를 눌러주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_8.webp)

EC2 액세스를 위한 키가 필요합니다. 새 키 페어를 받아주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_9.webp)

본인이 원하는 **키 페어 이름**을 설정해준 후 **키 페어를 다운로드**해주세요. 해준 후 꼭 **기억할 수 있는 곳**에 저장해주세요

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_10.webp)

이제 **인스턴스 시작**을 하면 준비 중이란 문구가 나옵니다. 시간이 조금 지난 후에 실행 중인 인스턴스를 확인해주세요.

실행 중이란 표현이 나옵니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_11.webp)

이때 저희가 생성한 **인스턴스**를 클릭해주시면 **연결**이란 버튼이 활성화됩니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_12.webp)

**거의 다 왔습니다!!** 저희가 생성한 우분투 인스턴스에 접속하기 위해 **ssh**를 사용해야 합니다.

먼저 메뉴에서 ssh 클라이언트를 클릭해줍니다. 그러면 메뉴 하단에 접속하는 방법에 관한 설명이 나옵니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/화면 캡처 2021-02-16 160910.webp)

이제 저희 컴퓨터에서 ssh를 통해 **인스턴스**에 접속해야 합니다. **명령 프롬프트**를 준비해주세요.

꼭 **관리자 권한**으로 실행해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_13.webp)

저희는 좀 전에 키 페어를 저장하였습니다. 본인이 키 페어를 저장해둔 경로를 복사해주세요.

명령어를 통해 cmd에서 해당 경로로 이동해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_14.webp)

#### \-해야 할 일은 2가지로 나누어집니다-

**키 페어의 권한 설정**과 **ssh를 통한 AWS 우분투 서버 접속**입니다.

먼저 키 페어를 살펴보겠습니다. 키 페어는 공개적으로 볼 수 없게 하기 위해 **권한을 설정**해주어야 합니다.

하지만 리눅스 환경이 아니기 때문에 적혀있는 chmod 코드를 사용하기 어렵습니다. 그래서 **수동으로 설정**해주어야 합니다.

1\. 속성을 클릭하고 **보안**이라는 메뉴에서 **고급**을 클릭해주세요

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_21.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_22.webp)

저희가 하려는 일은 권한의 제한입니다. 특정 파일 혹은 하위 폴더만 사용권한을 상속하지 못하게 해야 다른 곳에서 사용할 수 없습니다.

그 후 관리자만 허용하여 관리자만 사용 가능하게 해 줍니다.

권한 상속을 제한하기 위해 **상속 사용 안 함**을 클릭해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_15.webp)

명시적으로 변환해줍니다. 모두 제거하면 안 됩니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_16.webp)

권한을 관리자만 허용해주기 위해 보안 주체 중 **SYSTEM**과 **Administrators**를 제외하고 모두 제거해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_17.webp)

그럼 chmod 관련 설정이 마무리됐습니다. 이제 명령 프롬프트로 돌아와 주세요.

본인의 **ssh** 명령어를 아래에 입력해줍니다. (아래 이미지 맨 아래쪽에 보시면 ssh -i 있는 게 그 명령어입니다)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/화면 캡처 2021-02-16 160910_1.webp)

해당 경로에 복사 붙여 넣기 해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_18.webp)

잘 진행되셨다면 다행입니다.

만약 아래처럼 **permission denied** 가 뜬다면 당황하지 마시고 **다운로드한 키 페어의 명칭**과 명령어의 명칭이 일치하는지

확인해 보거나 혹은 관리자 실행으로 해주지 않았다면 **관리자 실행**으로 진행해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_19.webp)

아래처럼 잘 나오셨다면 리눅스 서버를 사용 가능하게 되신 겁니다 : - )

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/87/img_20.webp)

무리 없이 실행까지만 가보는 EC2 사용법이었습니다. 성실한 코딩 하세요
