---
title: "ubunto 18 root 계정 비밀번호 재설정(초기화)"
labels: ["OS","Linux","우분투","ubuntu"]
published: false
date: 2021-02-01T14:50:05+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 80
tistoryUrl: "https://yeolceo.tistory.com/80"
tistoryCategory: "OS/Linux"
tistoryTags: ["우분투","우분투","우분투","우분투","ubuntu","ubuntu","ubuntu"]
tistoryPostedAt: "2021-02-01 14:50:05"
language: ko
bloggerPostId: "1781435624473074856"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img.webp)

### **\-리눅스**

를 사용할 때 중요한 설정을 변경 및 저장해야 할 경우 **root 계정**의 사용이 필수적입니다.

중요한 설정에는 **보안적 요소**가 필요하기 때문입니다. 그 때문에 root 계정의 **비밀번호를 분실**하였을 경우

우분투 내에서 사용하는 주요한 명령어들을 사용할 때 **제약**이 생깁니다. 

때문에 root 계정의 비밀번호는 잊어버리면 안 됩니다. 하지만 **사람**인지라 **잊어버릴** 수 있습니다.

그래서 **비밀번호를 초기화** 및 **재설정** 할 방법이 존재합니다.

ubuntu 18을 통해 비밀번호 초기화 및 재설정 방법을 알아보겠습니다.   \*이후 ubuntu 18를 **우분투**로 표기

### **\-비밀번호 재설정 방법**

우분투를 실행하거나 실행되어있다면 restart를 통해 우분투를 재시작합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_1.webp)

시작하는 도중에 **Esc**를 누르고 있거나 **shift**를 누르고 있으면 아래와 같은 화면으로 넘어갑니다.

(연타하라는 분들도 계신데 제 경우에는 누르고 있어도 괜찮았습니다)

1\. 부트로더 GRUB의 첫 화면이 나옵니다. 아래 메뉴에서 2번째 옵션을 선택해줍니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_2.webp)

2\. 그다음 recovery mod를 선택해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_3.webp)

3\. root의 비밀번호 수정을 위해 메뉴 중 root를 선택해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_4.webp)

4\. 그렇면 텍스트를 입력하기 위한 화면으로 넘어갑니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_5.webp)

여기서 그냥 엔터를 쳤는데 넘어갔다면!! 아래의 명령어를 통해 **해결** 가능합니다.

```html
$ mount -rw -o remount /
$ passwd root
```

명령어를 통해 비밀번호 설정이 완료되었다면 **password updated successfully라는** 문구와 함께

비밀번호가 잘 적용되셨을 것입니다.

잘되셨나면 그대로 종료해주셨다가 다시 켜주시면 **root 계정**의 비밀번호가 설정하신 대로 **적용**될 것입니다.

### **\-하지만.. 안 된 경우**

궁금했던 저는 한번 더 비밀번호를 변경을 해보고 싶었습니다.  그리고 나오는 **Give root password for maintenance**

기존의 비밀번호를 유지보수를 위해 root 계정 비밀번호를 달라고 하네요.

비밀번호를 몰라서 하는 건데..

그렇다면 resume 을통해 원래대로 한번 돌아간 후 다시 메뉴창을 띄워줍니다. 그리고 e를 눌러주세요. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_6.webp)

아래 이미지와 같은 화면이 나옵니다. 맨 아래쪽으로 가줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_7.webp)

initrd 윗 라인이고 붉게 표시한 라인 부분에  **rw init=/bin/bash** <- 문장을 추가해줍니다.

**quiet** 끝에 구문을 다 타이핑해주셨다면  **ctrl+ x**를 통해 **적용**해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_8.webp)

저처럼 아래에 root 계정이 보이시다면 잘 진행하셨습니다. **passwd** 명령을 통해 비밀번호 **재설정**을 진행해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_9.webp)

본인이 설정하고 싶은 **root 계정**의 **비밀번호**를 입력해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_10.webp)

비밀번호 설정이 완료됐다면 reboot -f 명령어를 통해 리부트 해줍니다. 

다시 메뉴창으로 돌아왔다면 기다리거나 지금 화면에서 엔터키를 한번 눌러줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_11.webp)

엔터키를 한 번 더 누르고 resume 메뉴를 찾아주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_12.webp)

이 화면까지 잘 도달하셨다면 resume을 통해 노말 부트로 다시 시작해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_13.webp)

자 이제 모든 준비가 끝났습니다. 우분투를 실행하고 터미널을 사용해봅시다.

root 계정을 접속하기 위해 **su** 명령어와 **비밀번호**를 입력해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/80/img_14.webp)

여러분도 실행이 잘되셨길 바라고 고생하셨습니다. 성실한 코딩 하세요.
