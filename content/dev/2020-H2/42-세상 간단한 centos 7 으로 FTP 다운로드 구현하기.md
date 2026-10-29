---
title: "세상 간단한 centos 7 으로 FTP 다운로드 구현하기"
labels: ["OS","Linux","ftp","리눅스","centos"]
published: true
date: 2020-08-26T11:01:51+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 42
tistoryUrl: "https://yeolceo.tistory.com/42"
tistoryCategory: "OS/Linux"
tistoryTags: ["ftp","리눅스","centos"]
tistoryPostedAt: "2020-08-26 11:01:51"
language: ko
bloggerPostId: "6858921466545649054"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img.webp)

 이 글은 gui 버전입니다.   
cli글은 이쪽을 참고해주세요 ->  (금방올릴게요 ㄱㄷㄱㄷ)

## \- FTP 란

파일 전송 프로토콜(File Transfer Protocol)은 TCP/IP 프로토콜을 이용해서 서버와 클라이언트 사이에서 

파일을 전송하는 개념입니다. 서버에서 파일을 업로드하고 클라이언트에서 다운로드한다고 생각하시면 됩니다.

## \- 서버에서 해줄일

vmware 혹은 virtualbox에서 centos 7을 실행해줍시다.

터미널을 실행해줍니다. 그다음 root에서 사용하기 위해  su -  명령어를 입력합니다.  

아주 간단하게 FTP를 사용해주려 하는데 현재는 FTP 관련 기능을 가지고 있지 않습니다.

따라서 아래의 yum 명령어를 통해 vsftpd를 다운로드해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_1.webp)

이렇게 실행해주면 원래 없던 ftp라는 폴더가 var 경로에 생성됩니다. 

pub는 public을 의미하며 pub 폴더에 주로 파일을 업로드합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_2.webp)

자 이제 테스트를 위해 파일을 만들어주겠습니다. vi 텍스트 편집기를 활용하여 index.js 파일을 만들어줍시다.

(file1 은 개인적으로 테스트한 거니까 무시해주세요)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_3.webp)

vi 텍스트는 아래 이미지를 참고해주세요  i를 누르고 원하는 글을 입력 후 esc로 탈출해줍니다.

:wq가 저장 종료 구문입니다. 커맨드를 입력해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_4.webp)

첫 번째 커맨드는 설치한 ftp를 실행해주는 커맨드이고

두 번째 커맨드는 재부팅 시 자동 실행하겠다는 enable 커맨드입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_5.webp)

(저는 테스트 후 블로그용으로 다시 진행하기에 enable을 사용해도 service관련 설명 코드가 화면에 보이진 않습니다)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_6.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_7.webp)

ftp 방화벽을 해제해주는 이유는 외부에서 centos 7에 업로드되어있는 파일을 접근할 때 접근을 허용해주기 위함입니다.

벌써 centos7에서 해줄 일은 다끝났습니다.  서버는 자기역할을 완수했습니다. 

## \-클라이언트에서 해줄일

알드라이브 다운로드하시면 됩니다.

[https://www.altools.co.kr/](https://www.altools.co.kr/)

알드라이브를 통해 다운로드할 겁니다.

윈도그대로 쓰셔도되고 저처럼 vmware에서 윈도우 하나 더 실행하셔도 됩니다.

다운로드된 알드라이브를 실행하면아래와 같은 이미지가 출력됩니다.

내 사이트를 클릭하시고 추가 버튼 누르시면 됩니다. 저는 서버라고 이름을 설정했습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_8.webp)

오른쪽처럼 ip를 적으라고 나옵니다. centos7의 ip를 적어주시면 됩니다.

포트번호는 21로 했습니다.(포트번호 범위를 벗어나지 않는 한 숫자는 임의로 적어주시면 됩니다)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_9.webp)

수동으로 설정하신 거 아니면 명령어 ip addr을 사용하여 본인 ip를 찾아줍니다. 

아래 두 번째 동그라미쯤에 ip가 나옵니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_10.webp)

이렇게 확인된 본인 ip를 적어주면 됩니다. 이제 오른쪽 아래의 연결 버튼을 눌러줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_11.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/42/img_12.webp)

이제 다운로드해주시면 centos7 서버에서 FTP를 활용한 파일 다운로드가 완료됩니다. 

아주 쉽게 설명한 만큼 여러분도 이해가 잘 되셨길 바랍니다. 감사합니다.
