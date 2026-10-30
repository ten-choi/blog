---
title: "centos7 에서 node.js 설치하기 (How to install nodejs on centos)"
labels: ["OS","Linux","centos","centos7"]
published: true
date: 2020-10-13T13:29:28+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 53
tistoryUrl: "https://yeolceo.tistory.com/53"
tistoryCategory: "OS/Linux"
tistoryTags: ["centos","linux","centos7","centos"]
tistoryPostedAt: "2020-10-13 13:29:28"
language: ko
bloggerPostId: "6460481199096168096"
---
## **\-CENTOS 7 명령어**

### sudo

root 권한을 사용하기 위한 명령어입니다.

### curl 

command line에서 사용하는 데이터 통신 도구입니다. 업로드와 다운로드에 용이하여

필요한 데이터를 요청할 때 주로 사용합니다.

### bash

shell의 한 종류로 shell을 사용하여 컴퓨터에 명령을 텍스트로 작성하여 실행시킵니다.

### yum

yellodog update modified 약자이며 레드헷 계열에서 사용되는 패키지 설치 관리 도구입니다. 

## **\-node 설치를 위한 명령어 순서**

### **curl -sL [https://rpm.nodesource.com/setup\_12.x](https://rpm.nodesource.com/setup_12.x) | sudo bash -**

### **curl -sL https://rpm.nodesource.com/setup\_16.x | sudo bash -**

위의 주소는 Node.js 12 or 16 버전의 git url이며 바이너리 배포와 설정 지원 및 스크립트 사용에 대한 url입니다.

쉽게 말하면 node 특정 버전을 사용하기 위해 본인 컴퓨터에 node xx 버전 데이터를 받아주는 겁니다.

### **sudo yum clean all && sudo yum makecache fast**

yum clean all 은 cache를 모두 지워줍니다.

또한 makecacahe는 클리어 된 다음 cache를 최신으로 두어 작업 속도를 향상한다고 합니다.

### **sudo yum install -y gcc-c++ make**

GNU Compiler Comllection 가 gcc일 때 GNU C++ Compiler를 인스톨하는 것입니다.

### **sudo yum install -y nodejs**

이제 node.js를 인스톨합니다. 

### **node -v**

잘 설치되었는지 버전을 확인합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/53/img.webp)

**err case1**

**no package nodejs available 가 나온다면 curl로 yum 저장소에 node가 설치가 안돼 있다는 의미**

### yum install epel-release -y

Extra Packages of Enterprise Linux의 약어가 epel입니다. 리눅스 추가 패키지 인스톨하고 다시 아래의 명령어를 실행해주세요 그리고 다시 yum install node -y 해주세요. 하지만 이렇게 하면 원하는 버전의 정보가 없어서 node 기본 버전이 설치됩니다.

잘되셨길 바랍니다 성실한 코딩 하세요.
