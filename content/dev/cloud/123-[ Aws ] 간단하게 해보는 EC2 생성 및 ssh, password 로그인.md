---
title: "[ Aws ] 간단하게 해보는 EC2 생성 및 ssh, password 로그인"
labels: ["Cloud","aws","ec2"]
published: false
date: 2022-02-17T12:37:19+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 123
tistoryUrl: "https://yeolceo.tistory.com/123"
tistoryCategory: "Cloud/aws"
tistoryTags: ["ec2","ec2","ec2"]
tistoryPostedAt: "2022-02-17 12:37:19"
language: ko
bloggerPostId: "4187514660251497526"
---
#### 환경 

Window 10  
RedHat 8

#### 개요

AWS에서 EC2기능을 통해 RedHat 인스턴스를 만들고 탄력적 IP 설정과 로그인까지 한번에 해결하세요

#### 목차

-   **EC2** **인스턴스** **만들기**
-   **새** **키** **페어** **만들기**
-   **로그인을** **위한** **키** **페어** **권한** **설정하기**
-   **로그인** **테스트하기** **1**
-   **SSH** **로그인을** **Pem****이** **아닌** **PW** **로그인으로** **변경하기** 
-   **SSH** **로그인** **테스트하기** **2**

## **\- EC2 인스턴스 만들기**

aws 사이트에서 EC2 서비스를 찾아봅시다. EC2 카테고리를 클릭해주시면 인스턴스 시작이라는 버튼을 확인할수있습니다. 버튼을 눌러 인스턴스를 생성합니다.

1\. AMI 선택

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img.webp)

Amazon Machine Image(AMI)를 선택을 해야 합니다.

원하는 Linux가 있다면 선택해주시고 저는 Red Hat을 선택하겠습니다.

![ㅡ](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_1.webp)

2\. 인스턴스 유형 선택

프리티어 사용 가능하다고 있지만 1cpu 1g 메모리 이기 때문에 속도도 느립니다. 소규모 테스트 용도로만 사용해주세요

저는 앞으로 사용할 서버이기때문에 2 cpu에 8메모리의 인스턴스를 선택했습니다.

3\. 인스턴스 구성

따로 IP 설정이나 네트워크 설정을 하지않고 기본설정으로 넘어갑니다.

4\. 스토리지 추가 

기존 용량에서 줄이면 에러가 뜨는걸보니 가격과 관련된 정책이 있을듯합니다. 기존설정 그대로 진행합니다.

5\. 태그 추가

태그추가하지않습니다.

6\. 보안 그룹 구성

ssh로그인이나 인바운드, 아웃바운드 가능한포트 및 접속가능한 ip를 이곳에서 설정이 가능합니다. 추후 수정도 가능합니다. 따라서 기존 ssh 로그인 기본설정을 유지한채 진행합니다.

7\. 검토

모든 설정이 완료되었다면 검토 및 시작을 눌러줍니다. 

키페어 생성에 관한 알림창이 나옵니다.

키페어어 생성은 처음하시는 분이시라면 새 키 페어를 바로 생성하시는것보다 아래의 양식대로 먼저 한번 만들어보는것을 추천합니다.

기존 창을 그대로 두고 새창에서 새 키 페어를 만들어주세요

## **\- 새 키 페어 만들기**

카테고리에서 키 페어 부분을 클릭하고 키페어 생성버튼을 눌러주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_2.webp)

원하는 이름을 만들어 줍니다.

공개키 알고리즘인 RSA를 선택해주세요.  AWS에서 퍼블릭 키를 저장하고 유저에게 프라이빗 키 파일을 주는 형태입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_3.webp)

생성 후 키 페어가 생성되며 pem 파일 하나가 다운로드됩니다.  
(이 파일은 단 한번 다운로드 가능하기 때문에 잘 보관해야 합니다)

인스턴스 마지막으로 돌아가서 지금 만든 키페어를 적용하고 인스턴스 생성을 마무리해주세요.

인스턴스 생성이 완료되셨습니다~ 이제 로그인을 시도해주세요

cmd 창을 켜주시고 pem 파일을 이용한 ssh 로그인을 진행해주세요.

```html
ssh -i D:\yourpath\my_key.pem  ec2-user@11.11.11.11
```

Permission denied 에러가 뜬다면 로그인 직전까지 잘 완료되신겁니다.

## **\- 로그인을 위한 키 페어 권한 설정하기**

방금 다운로드 받은 pem 파일은 권한설정을 따로 해주지않으면 권한 문제로 에러가 뜨는 경우가 있습니다. linux에서는 chmod 설정으로 간단히 바꿀 수 있지만 window에서는 그렇지 않습니다. 

key파일을 우클릭하고 속성에서 보안 탭을 눌러줍니다.

하단에 고급이라고 쓰여있는 부분을 클릭해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_4.webp)

상속 사용 안 함을 눌러줍니다. 모든 권한을 제거합니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_5.webp)

다 사라지면 추가를 눌러서 다시 추가해주어야 합니다.

보안 주체 선택을 눌러주세요

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_6.webp)

고급을 눌러주세요

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_7.webp)

지금 찾기를 클릭하여 본인 pc의 유저를 찾아 등록해줍니다.

아래와 같이 읽기 및 실행과 읽기는 권한이 제공되어야 pem파일을 읽을 수 있습니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/123/img_8.webp)

하나의 유저만 남았다면 확인 후 로그인을 진행해주세요.

## **\- 로그인 테스트하기 1**

아래와 같이 pem 파일을 선택해서 로그인을 진행해야 합니다.

ec2-user는 aws의 기본 유저입니다. 

ssh 로그인을 할 건데 i 옵션은 rsa의 파일 위치를 지정하는 옵션이고 옆에 경로를 적어줍니다.

유저명@서버 IP를 붙여주면 로그인 명령어 완료입니다. 

```css
ssh -i D:\yourpath\my_key.pem  ec2-user@11.11.11.11
```

로그인이 완료되었습니다.

## **\- SSH 로그인을 Pem이 아닌 PW 로그인으로 변경하기** 

```html
# sudo su
# passwd
```

아래와 같이 pem 파일을 선택해서 로그인을 진행해야 합니다. 

```html
# vi /etc/ssh/sshd_config
```

ec2-user는 aws의 기본 유저입니다. 

```html
PermitRootLogin yes PasswordAuthentication yes
```

ssh 로그인을 할 건데 i 옵션은 rsa의 파일 위치를 지정하는 옵션이고 옆에 경로를 적어줍니다.

```html
# service sshd restart
```

이러면 완료됩니다. 

## **\- 로그인 테스트하기 2**

아래와 같이 pem 파일을 선택해서 로그인을 진행해야 합니다. 

ec2-user는 aws의 기본 유저입니다. 

ssh 로그인을 할 건데 i 옵션은 rsa의 파일 위치를 지정하는 옵션이고 옆에 경로를 적어줍니다.

유저명@서버 IP를 붙여주면 로그인 명령어 완료입니다

```css
ssh -i D:\yourpath\my_key.pem  ec2-user@11.11.11.11
```

이렇게 pw를 통한 로그인까지 완료하였습니다. 

처음 인스턴스를 만들었을 때 방화벽은 존재하지 않기 때문에 방화벽 관련 설정도 진행해주시면 좋을듯합니다. 

성실한 코딩 하세요.
