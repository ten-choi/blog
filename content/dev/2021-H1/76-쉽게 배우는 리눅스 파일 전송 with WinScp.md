---
title: "쉽게 배우는 리눅스 파일 전송 with WinScp"
labels: ["ETC","ETCLanguage","리눅스","win"]
published: false
date: 2021-01-13T18:02:56+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 76
tistoryUrl: "https://yeolceo.tistory.com/76"
tistoryCategory: "ETC/ETCLanguage"
tistoryTags: ["리눅스","리눅스","리눅스","win","리눅스"]
tistoryPostedAt: "2021-01-13 18:02:56"
language: ko
bloggerPostId: "1434143741498156615"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img.webp)

#### **\-WinScp** 

윈도에서 사용하는 **오픈소스** 프로그램으로 **SFTP**나 **FTP**가 가능합니다.

로컬 환경의 컴퓨터를 이용해서 원격 서버에게 파일 전송하거나 수신하는 것을 도와주는 프로그램입니다.

(SFTP = 보안 파일 전송 프로토콜)

(FTP = 파일 전송 프로토콜)

#### **\-다운로드**

먼저 구글링을 통해 검색해줍니다. **WinScp**를 검색해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_1.webp)

**WinScp** 공식 홈페이지입니다.  표시해놓은 부분을 클릭하여  다운로드를 진행해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_2.webp)

다운로드가 표시된다면 계속을 누르고 완료됐다면 클릭하여 **실행**해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_3.webp)

설치 화면이 나오면 그대로 진행해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_4.webp)

별다른 이유가 없으시다면 **전체 업그레이드**를 권장합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_5.webp)

아래처럼 설치가 **완료**되셨다면 **완료**를 눌러주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_6.webp)

설치법은 이것으로 마무리가 됩니다. **아이콘**을 실행해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_7.webp)

#### **\-사용법**

**아이콘** 클릭하여 실행해주셨다면 아래와 같은 **로그인 창이** 등장합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_8.webp)

**1.**  파일 프로토콜은 **SFTP로** 설정해줍니다. **SFTP는** **SSH** 파일 전송 프로토콜입니다. **SSH**는 **텔넷**이란 네트워크 연결 프로토콜에 보안을 추가한 것입니다. 

**2.** 원격으로 파일을 전송하고 싶은 리눅스의 IP를 **호스트 이름(H)**에, 리눅스에서 원격용으로 열어놓은 포트 번호는 **포트 번호(R)에** 적어주세요. 잘 모르시겠다면 테스트할 땐 해당 리눅스 서버의 **방화벽**을 끄고 연습해보셔도 좋습니다.

3\. 사용자 **이름(U)은** **root** 계정 쓰시고 **비밀번호(P)**는 해당 계정의 비밀번호를 입력해주세요.

자 모든 입력이 올바르게 끝났다면 **로그인 버튼을** 눌러주세요.

혹시 비밀번호를 **틀렸을 경우** 이러한 이미지가 출력됩니다. 올바른 비밀번호를 입력해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_9.webp)

### **자 성공적으로**

프로그램이 실행되었습니다. 파일을 옮겨보시면 아주 **유용한 무료 오픈소스 프로그램이란 걸** 알 수 있으실 겁니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/76/img_10.webp)

간편하게 **WinScp를** 통해 파일을 전송하는 방법을 알아보았습니다.

잘 마무리하셨길 바랍니다. 성실한 코딩 하세요!
