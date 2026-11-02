---
title: "간단하게 Centos7 고정 IP 설정하기"
labels: ["OS","Linux","centos7","centos"]
published: true
date: 2021-01-12T18:02:37+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 75
tistoryUrl: "https://yeolceo.tistory.com/75"
tistoryCategory: "OS/Linux"
tistoryTags: ["centos7","centos7","centos7","centos7","centos"]
tistoryPostedAt: "2021-01-12 18:02:37"
language: ko
bloggerPostId: "2495088314521386285"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/75/img.webp)

### **\-CentOS7에서 고정 IP 설정하는 법**

먼저 **CentOS7을** 실행한 후 터미널을 실행해줍니다.  su - 명령어를 통해 계정을 **root**계정으로 변경해줍니다. 

(네트워크 설정 파일을 변경할 때 권한이 필요하기 때문입니다)

```html
$ su -
```

![비번은 기억하시는데로 ~](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/75/img_1.webp)

아래의 경로가 네트워크 설정 파일 경로입니다. 텍스트 에디터(vi) 명령어로 실행해줍니다.

( 파일명이 조금 다를 경우 해당 경로에서 찾아 실행합니다 )

```html
$ vi /etc/sysconfig/network-scripts/ifcfg-ens33
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/75/img_2.webp)

#### **파일 설정 변경**

명령어를 입력하면 아래와 같은 코드가 나옵니다.

```html
TYPE="Ethernet"
PROXY_METHOD="none"
BROWSER_ONLY="no"
BOOTPROTO="dhcp"
DEFROUTE="yes"
IPV4_FAILURE_FATAL="no"
IPV6INIT="yes"
IPV6_AUTOCONF="yes"
IPV6_DEFROUTE="yes"
IPV6_FAILURE_FATAL="no"
IPV6_ADDR_GEN_MODE="stable-privacy"
NAME="ens33"
UUID="5c1140e4-f15f-4a78-9bd9-c02f371d720a"
DEVICE="ens33"
ONBOOT="yes"
```

하단의 코드를 복사 붙여 넣기 해주시고 아래쪽에 부연설명 추가했습니다.

```html
TYPE="Ethernet"
PROXY_METHOD="none"
BROWSER_ONLY="no"
#BOOTPROTO="dhcp"                
DEFROUTE="yes"
IPV4_FAILURE_FATAL="no"
IPV6INIT="yes"
IPV6_AUTOCONF="yes"
IPV6_DEFROUTE="yes"
IPV6_FAILURE_FATAL="no"
IPV6_ADDR_GEN_MODE="stable-privacy"
NAME="ens33"
UUID="5c1140e4-f15f-4a78-9bd9-c02f371d720a"
DEVICE="ens33"
ONBOOT="yes"

# this code is for static IP   
BOOTPROTO="none"
IPADDR=192.168.219.144
PREFIX=24
GATEWAY=192.168.219.1
DNS1=168.126.63.1
DNS2=168.126.63.2
ONBOOT="yes"
PEERDNS=no
```

#### **변경된 부분 설명**

1\. 본인이 추가할 라인위에 주석(#을 이용)으로 어떤 코드를 추가했는지 기록해 줍니다.

2\. BOOTPROTO을 dhcp로 할 경우 동적으로 ip를 자동 결정하기 때문에 기존의 것을 주석 처리해줍니다. 그리고 새로 none으로 설정해줍니다.

3\. IPADDR 은 현재 CentOS7에서 인터넷 사용이 가능하다면 기존 ip와 동일하게 설정한 후에서 끝자리만 원하시는 걸로 변경해서 기입해주세요.

4\. PREFIX 고정 ip 사용 시에 prefix 나 netmask를 적어주어야 합니다.

5\. GATWAY는 무선공유기 쓰시면 웬만하면 본인 ip 3칸 + 끝자리 1이십니다.

6\. DNS 1과 2는 1은 기본, 2는 보조를 뜻하며 적어놓은 dns ip는 kt 서버의 ip입니다.

7\. ONBOOT 켜질 경우에도 이설 정이냐고 물어보면 **yes**로 합니다.

8\. PEERDNS는 **dhcp**로부터 받던 특정 정보를 받을지에 대한 유무입니다. 저희는 **none**으로 했으니 꺼줍니다.

아래 명령어를 통해 저장합니다. (세미콜론 누르고 wq 하시면 됩니다.)

```html
$ :wq
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/75/img_3.webp)

명령어를 통해 네트워크를 한번 재시작해줘야 변경한 ip가 적용이 됩니다.

```html
systemctl restart network
```

 **ip addr** 명령어를 통해 ip를 확인해주세요. 잘 마무리되셨나요?  이상 **centos7**의 고정 ip 설정이었습니다.

잘마무리하셨길 바랍니다. 성실한 코딩 하세요!
