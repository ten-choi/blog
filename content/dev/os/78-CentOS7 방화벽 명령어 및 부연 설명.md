---
title: "CentOS7 방화벽 명령어 및 부연 설명"
labels: ["OS","Linux","centos7"]
published: false
date: 2021-01-25T18:35:09+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 78
tistoryUrl: "https://yeolceo.tistory.com/78"
tistoryCategory: "OS/Linux"
tistoryTags: ["centos7","centos7","centos7","centos7"]
tistoryPostedAt: "2021-01-25 18:35:09"
language: ko
bloggerPostId: "8892064234724327494"
---
### **\-방화벽이란**

신뢰할 수 있는 허가된 네트워크를 제외한 경우, 네트워크를 통해 외부에서 내부로의 접속을 막는 네트워크 보안 시스템입니다.

**CentOS7**은 **firewalld**라는 방화벽이 기본으로 탑재되어있습니다. 이 방화벽에 대한 설정은 **zone**(영역)을 이용하여

적용합니다.  **public**이란 이름의 **zone**을 예로 들어 설명하겠습니다.

**CentOS7**에서는 방화벽의 기본 설정이 **public**을 명칭으로한 **zone**이 설정되어있습니다.  

/etc/firewalld/zones/public.xml 경로에 말이죠.

그래서 **public** 이란 이름의 **zone**에 설정을 추가하면 **public.xml** 파일에 저장됩니다. 

다른 이름의 **zone**을 사용하여 기존과 다른 설정을 저장해놓고 사용할 수도 있습니다.

### **\-명령어 실행해보기**

**CentOS7**을 사용할 때 **방화벽**을 다루어야 할 경우 유용하게 사용되는 **명령어**를 모아놓았습니다.

먼저 **CentOS7**을 실행해줍니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/78/img.webp)

아래의 설명을 통해 명령어를 하나씩 입력해보면서 테스트해주세요 (**root** 계정에서 진행했습니다)

**방화벽이 실행 중인지 확인**

실행 중이면 **running** 정지상태면 **not running** 을 터미널에 출력합니다.

```html
[YEOL@localhost]# firewall-cmd --state
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/78/img_1.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/78/img_2.webp)

**방화벽의 기능을 정지**

방화벽을 통째로 정지하기 때문에 방화벽에 의한 문제인지 판별할 때 요긴합니다.

```html
[YEOL@localhost]# systemctl stop firewalld
```

**방화벽의 기능을 실행**

방화벽을 정지해두었다면 방화벽을 실행해줍니다.

```html
[YEOL@localhost]# systemctl start firewalld
```

**방화벽 변경 시 설정 적용**

방화벽 설정이 변경되었다면 **reload**를 통해 설정을 적용해줍니다.

```html
[YEOL@localhost]# firewall-cmd --reload
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/78/img_3.webp)

**부팅 시 적용되는 설정**

**disable** 명령어를 사용하면 재부팅 시에도 방화벽이 실행되지 않습니다. (일반적으로 재부팅 시 방화벽이 실행됩니다)

```html
[YEOL@localhost]# systemctl disable firewalld
```

**enable** 명령어를 사용하면 재부팅 시에 방화벽이 실행됩니다.  

```html
[YEOL@localhost]# systemctl enable firewalld
```

**접근 가능 포트 추가 제거**

**public**이란 명칭의 **zone**에 **permanent**하게 포트를 **add** 하겠다는 의미입니다. (영어를 해석하며 사용하면 이해에 좋습니다)

```html
[YEOL@localhost]# firewall-cmd --permanent --zone=public --add-port=3000/tcp

[YEOL@localhost]# firewall-cmd --permanent --zone=public --add-port=3000-6000/tcp //구간 추가
```

**public**이란 명칭의 **zone**에 **add** 되어있던 포트를 **permanent** 하게 **remove** 하겠다는 의미입니다.

```html
[YEOL@localhost]# firewall-cmd --permanent --zone=public --remove-port=3000/tcp

[YEOL@localhost]# firewall-cmd --permanent --zone=public --remove-port=3000-6000/tcp //구간 제거
```

설정을 변경했다면 변경된 설정을 적용해 주기 위해 위쪽에서 설명드렸던 **reload** 명령어를 사용해야 합니다.

**방화벽의 모든 zone에 대한 정보**

방화벽의 **인터페이스, 서비스, 포트** 등 관련 정보를 보여줍니다. 변경된 사항을 체크할 수 있습니다.

```html
[YEOL@localhost]# firewall-cmd --list-all
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/78/img_4.webp)

간단하게 사용해보는 **CentOS7** **방화벽 명령어**였습니다. 쉽게 이해하셨길 바랍니다!

성실한 코딩 하세요.
