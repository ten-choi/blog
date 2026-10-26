---
title: "초간단! CentOS 부팅용 USB 만들기"
labels: ["OS","Linux","centos"]
published: false
date: 2020-12-22T11:15:15+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 62
tistoryUrl: "https://yeolceo.tistory.com/62"
tistoryCategory: "OS/Linux"
tistoryTags: ["centos","centos","centos","centos"]
tistoryPostedAt: "2020-12-22 11:15:15"
language: ko
bloggerPostId: "7044233460346142758"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img-png.webp)

Centos boot usb를 만들기 위한 글입니다. 

그럼에도 iso 파일을 ubuntu로 다운로드하실 경우 부팅 usb를 만드는 과정 자체는 동일합니다.

### **\- Centos 7 iso Download**

아래 링크로 들어가셔서 **초록색 라인** 밑에 있는  iso 다운로드 링크를 클릭해주세요.

초록 라인은 해당 미러사이트의 iso images를 사용하란 의미입니다.

[isoredirect.centos.org/centos/7/isos/x86\_64/](http://isoredirect.centos.org/centos/7/isos/x86_64/)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_1-png.webp)

어느 라인을 클릭하셔도 큰 차이는 없습니다. (저는 카카오로 들어갔습니다 대기업..)

아래 이미지 대로 **분홍 박스의 파일**을 클릭해주시면 다운로드가 시작됩니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_2-png.webp)

다운로드가 진행중이시라면 다음으로 넘어가 주세요.

### **\- 부팅용 USB 만들기**

위에 서 다운로드한 **centos 7** 파일의 용량은 4.4GB 일 것입니다. 여유 있게 8GB 이상의 usb를 준비해줍니다.

그리고 **rufus** 라는 **usb 부팅 지원 프로그램**을 다운로드해줍니다.  오늘의 키포인트입니다!

 **rufus** 를 다운로드해줍시다.   

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_3.webp)

공식 홈페이지를 살펴주시고 아래 분홍 네모칸을 클릭해주면 됩니다!!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_4.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_5.webp)

다운로드가 완료되셨다면 위의 exe 파일이 다운로드되셨을 겁니다.

곧바로 실행해줍시다. (iso 파일이 다운로드 완료상태가 아니라면 진행을 멈춰주세요.)

1\. 자신의 usb를 선택합니다.

2\. 본인이 다운로드한 centos 7 iso 파일을 클릭해줍니다. 

3\. usb 이름 설정입니다.

4\. FAT32 or Large FAT32를 선택해주시고 없다면 기본을 선택해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_6.webp)

설정이 완료되었다면 시작을 눌러주세요.

![iso 이미지 모드로 쓰기(권장) 선택](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img.webp)

![포맷 여부를 묻는 알림](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_1.webp)

자 이제 모든 설정이 끝났습니다.  이제 완료되기만을 기다려주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/62/img_2.webp)

축하드립니다. centos boot usb를 다 만드셨습니다. 

실제로 사용하실 때는 데스크톱의 usb 2.0 포트를 사용하시는 걸 추천합니다. 성실한 코딩 하세요.
