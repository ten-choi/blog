---
title: "간단하게 배우는 윈도우에서 centos 7 설치 진행하기"
labels: ["OS","Linux","centos7","vmware15.5","vmware"]
published: true
date: 2020-10-30T11:09:54+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 33
tistoryUrl: "https://yeolceo.tistory.com/33"
tistoryCategory: "OS/Linux"
tistoryTags: ["centos7","vmware15.5","vmware"]
tistoryPostedAt: "2020-10-30 11:09:54"
language: ko
bloggerPostId: "533643286864064617"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img.webp)

## \- 리눅스란

리눅스는 오픈소스 운영 체제입니다. 일반 컴퓨터를 운용할때 윈도우를 설치하는것처럼

서버 컴퓨터를 운용할때는 서버에 맞는 운영체제가 필요하고 그중 하나가 리눅스입니다.

## \- VMware 설치

한 컴퓨터에서는 운영체제가 2개일수 없습니다. 그렇기때문에 가상머신을 이용하여 저희 컴퓨터에

가상으로 리눅스 운영체제를 실행해주어야 합니다. 그렇기 위해 VMware 라는 응용프로그램을 사용합니다.

하단의 url을 참고해주세요.

[yeolceo.tistory.com/31](https://yeolceo.tistory.com/31)

## \- Centos7 설치하기

가상머신에서 리눅스를 사용해주기위해선 iso 라는 운영체제가 들어있는 파일을 필요로합니다.

저희는 centos7을 사용해줄 계획입니다.

[mirror.kakao.com/centos/7.8.2003/isos/x86\_64/](http://mirror.kakao.com/centos/7.8.2003/isos/x86_64/)

위의 URL을 따라 아래의 DVD 라 적혀있는 iso 파일을 설치해줍니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_1.webp)

다운로드 하는데 약간 시간이 걸립니다.  웹툰한회정도 보고오셔도 무방합니다 하하  

## \- centos 7 설치 진행하기

자 이제 VMware와 ISO 파일 모두 설치가 완료되었기때문에 이 두가지를 이용하여

centos7을 실행해봅시다.

먼저 하단의 file 에서 new를 클릭해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_2.webp)

아래와같이 화면이 등장했다면 본인이 다운로드 받은 iso 파일을 선택해줍니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_21.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_22.webp)

여기서 이름을 설정해주는 부분인데 나중에 다른 가상 운영체제를 만들수있으므로

본인이 구분할수있는 명칭을 지어줍시다. 용도에 따라 적어주시면 됩니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_3.webp)

이 가상머신이 어느정도의 용량을 차지해도 되는지 미리 설정해주는 부분입니다.  

여유가 없으시면 20GB 정도 해주셔도 좋습니다. 여유가 있으시면 50GB 내외로 설정해주세요.

아래 체크 사항은 파일을 하나로 하냐 분산해서 저장하냐인데 

50GB 하나짜리 통으로 만들면 미약하게 성능이 증가합니다.

하지만 필요한 데이터를 복사해서 가져올때 불편할수도있으니 저는 멀티플을 선택했습니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_4.webp)

아래 노란색 체크를 한 커스터마이즈 하드웨어라는 버튼을 클릭해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_5.webp)

이기능은 저희가 가상머신에 어느정도의성능을 부여해줄지 체크해줍니다. 

본인 컴퓨터의 사양에서 가져오는것이기때문에 여유가 있으신 분만 듬뿍 설정해줍시다.

저는 회사 컴이라 저정도만 해줬습니다..  아래는 메모리설정입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_6.webp)

여기는 cpu 코어 갯수입니다. 출력문제인데 그냥 하나해줘도 큰문제없습니다. 개발용이면요

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_7.webp)

여기는 인터넷설정을 어떻게 해줄지입니다. 브릿지는 기존의 운영체제와 인터넷을 연결한 상태입니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_8.webp)

자 이제 모든 설정을 마무리했습니다. 이제 그냥 진행만해줍시다.

그러면 아래와같은 화면이 나옵니다. 

이제 얼마남지 않았습니다.!!!  언어를 설정해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_9.webp)

아래와 같은 화면이 나올것입니다. 

여기서 필요한 아래를 따라가면서 살펴주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_10.webp)

키보드 레이아웃입니다. 키보드를 클릭하여 영어를 선택해주세요. 

저희는 영어도 쓰고 한글도 써야하기 때문입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_11.webp)

이제 이화면으로 다시돌아오면 설치 대상을 선택해줍시다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_12.webp)

이게 저희가 설치하려는 장치입니다. 여기서 설정을 구분해줍니다.

해당 40GIB 여유공간을 가진 디스크를 선택하고 파티션설정을 누른 후에 완료를 클릭해주세요.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_13.webp)

파티션 설정은 아래와같이 해주시면됩니다. boot와 swap에 기본적인 용량만 주고

'/' 가 나머지 용량들이니 남은 메모리는 슬레쉬에 몰빵해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_14.webp)

완료하셨다면 아래의 창에서 네트워크를 선택해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_15.webp)

클릭하면 아래처럼 나오는데 처음엔 끔으로 되있을겁니다. 설정을 자신의 컴퓨터에 맞게 넣어줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_16.webp)

설치시작을 눌러주세요 그럼 시작됩니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_17.webp)

혼자 개발용으로 쓰실거면 root암호만 추가셔도됩니다. 

root는 모든 권한을 가진 계정이며 

사용자는 권한을 제한한 계정입니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_18.webp)

계정을 바로 만들어줍니다. 꼭 pw는 어딘가에 적어놓으시는걸 추천합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_19.webp)

고생하셨습니다. 이제 설치가 완료되기를 기다리면 아래와같은 화면이 등장할것입니다. 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/33/img_20.webp)
