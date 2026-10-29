---
title: "vmware 를이용해 ubuntu 데스크탑용 간단히 실행하기"
labels: ["OS","Linux","ubuntu","vmware"]
published: true
date: 2020-07-17T12:00:20+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 34
tistoryUrl: "https://yeolceo.tistory.com/34"
tistoryCategory: "OS/Linux"
tistoryTags: ["ubuntu","vmware","ubuntu"]
tistoryPostedAt: "2020-07-17 12:00:20"
language: ko
bloggerPostId: "5795325717038077482"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_8.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_9.webp)

## \- 우분투 설치하기

자 이제 우분투를 설치하러 가보겠습니다. 

저희가 사용할 버전은 18.04 버전입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img.webp)

[https://releases.ubuntu.com/18.04/](https://releases.ubuntu.com/18.04/)

[64-bit PC (AMD64) desktop image](https://releases.ubuntu.com/18.04/ubuntu-18.04.4-desktop-amd64.iso)를 설치하시면됩니다. 

검색을 하거나 위의 링크만 따라가도 iso 파일을 다운로드 가능합니다. 

설치가 완료되었다면 vmware workstation 15.5(자신이 설치한 버전)을 실행합니다.

## \- VMware 실행

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_1.webp)

player -> file -> new virtual machine을 선택합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_2.webp)

해당 화면이 나온다면 경로에 본인이 설치한 iso파일을 선택합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_3.webp)

사용할 이름들과 비밀번호 설정입니다. **readme.txt 파일을 만들어 적어둔내용을 따로 저장해둡시다.**

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_4.webp)

용량을 저는 50gb로 설정했습니다. 용량은 본인 컴퓨터의 용량을

나누어주는 것이기 때문에 잘 고민해서 기입해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_5.webp)

원하는 설정이 잘 기입되었나 설정해줍니다. 

커스터마이즈는 웬만하면 할 필요 없이 기본 설정으로 진행해도 좋습니다. 단 본인 컴퓨터가 스펙이 낮다면

메모리나 cpu코어를 잘선택해야할것입니다.

단.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_6.webp)

커스터마이즈를 네트워크 설정 부분입니다.  크게 3개로 나눠집니다.

* * *

\- Bridge 

   공유기를 통해 외부 네트워크와 통신을 가능하게 합니다. 공유기에서 host pc , guest pc에 ip를 

   할당해주는 것입니다.

\- Nat (network address translation) 

   host pc에서 ip를 할당받으면 내부의 dhcp를 통해 ip를 할당합니다. 위에 거는 공유기를 통한 연결이면

   이건 host pc를 통한 연결입니다.

\- Host-only

   host pc와 내부 가상 머신들끼리만 통신이 가능합니다. ip할당이 따로 없으니 인터넷도 안될 거고 필요한 경우가

   아니라면 저는 잘 쓴 적이 없습니다.

이제 기본적인 설정이 끝났고 그대로 전부 Next로 넘어가면 아래와 같은 화면이 나옵니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/34/img_7.webp)

축하드립니다. 이제 인스톨이 완료되면 처음 본인이 설정한 pass를 통하 os를 실행할 수 있습니다.
