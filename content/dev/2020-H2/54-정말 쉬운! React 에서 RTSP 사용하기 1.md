---
title: "정말 쉬운! React 에서 RTSP 사용하기 1"
labels: ["TS","JS","react","rtsp","streamdian"]
published: true
date: 2020-10-20T17:07:10+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 54
tistoryUrl: "https://yeolceo.tistory.com/54"
tistoryCategory: "TS, JS/react"
tistoryTags: ["react","react","rtsp","streamdian","react"]
tistoryPostedAt: "2020-10-20 17:07:10"
language: ko
bloggerPostId: "8822024657025768002"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img.webp)

\-해당 글은 streamedian 사이트의 rtsp 기술을 참조합니다. 윈도에서 개발하시는 분들이 RTSP 하시기에 적합하며 

실무라면 라이선스 구매나 리눅스 환경에서 실행을 위한 공부가 필요할 수 있습니다.

## **\-RTSP** 

**Real time streaming protocol**의 스트리밍 서버를 실시간으로 제어하기 위해 설계된 프로토콜입니다.

예를 들면 cctv 같은 실시간 영상을 재생할 때 RTSP나 HLS 등의 프로토콜이 적용됩니다.

## **\-Streamdian**

Streamdian이란 개발자의 편의성을 위해 **웹소켓을 통한 rtsp 스트리밍을** 지원해주는 비디오 플레이어입니다.

바로 검색해서 공식 홈페이지를 참조해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_1.webp)

먼저 소켓통신을 위한 준비를 시작합시다.

홈페이지의 첫 화면은 아래와 같을 것입니다. 붉은 선이 그어진 부분을 클릭합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_2.webp)

다운로드할 수 있는 버전이 여러 가지가 있고 저희는 아래 선이 그어진 **react** 파일을 다운로드해줍니다!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_3.webp)

자 다운로드가 완료되었다면 아래와 같은 압축파일이 실행될 테니 본인이 원하는 폴더를 만들어 압축을 해체합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_4.webp)

폴더를 만들고 압축 풀기를 완료했다면 해당 폴더에서 npm install을 실행해줍니다.

(필요 라이브러리가 모두 설치됩니다!!)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_5.webp)

**npm install**을 통해 모듈 설치가 완료됐나요? 그렇다면 npm start 명령어를 통해 실행합시다!!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_6.webp)

성공적으로 실행을 완료하셨나요?  벌써 절반이 끝났습니다.

실행을 하면 아래와 같은  화면이 보입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_7.webp)

sample이라고 적혀있는 url을 기입하고 set을 눌러 영상을 실행해줍니다. 

하지만 실행이 되지 않는다면 그건 당연한 것입니다. 

왜냐하면 rtsp를 사용하기 위해 streamedian은 service의 형태로 소켓통신을 지원하는데 저희는 

그걸 설치하지 않았기 때문입니다. 바로 설치 가보겠습니다!!

## \-웹 소켓 설치

자 이제 끝이 거의 다 왔습니다. 조금만 더 힘 내주세요!!

이번엔 빨간 줄이 그어져 있는 RTSP 소켓 클라이언트를 다운로드 진행해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_8.webp)

아래를 찾아보면 자신이 속한 운영체제를 선택해주세요. 저는 윈도 10을 선택했습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_9.webp)

순서대로 next 누르시면 인스톨이 완료가 됩니다. 빠른 연타!

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_10.webp)

설치가 완료되었다면 작업 관리자를 실행해주세요.

작업 관리자 서비스 창에 아래와 같은 **streamedian proxy service** 가 생겼나요?

그럼 잘 완료된 것입니다.!!! 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_11.webp)

\[가끔 서비스 중지되니까 작업 관리자에서 해당 서비스 선택 후 우클릭 누르시고 서비스 시작 누르시면 됩니다\]

이제 다시 저희가 실행한 **react**로 돌아가 줍니다.

**rtsp url**을 input 칸에 넣어주고 set 버튼을 클릭해주면 해당 url에 맞는 영상이 실행되는 구조입니다.

(샘플 url을 구해서 테스트해봤는데 rtsp 자체가 이상한 건지.. 영상 플레이는 안되지만 약 9분 남짓한 영상이라는 표시가 뜹니다... )

개인의 rtsp url이 있으신 분들은 써보시면 바로 사용 가능하십니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/54/img_12.webp)

본인의 react에 rtsp를 넣어 실행하고 싶다 하시는 분들은 **\[정말 쉬운! React 에서 RTSP 사용하기 2  -YEOL\]**를 봐주세요.

도움이 되셨길 바랍니다. 성실한 코딩하세요.
