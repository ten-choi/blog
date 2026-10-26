---
title: "Window MariaDB 비밀번호 분실 시 수정 (MySql root password reset and update windows)"
labels: ["DB","rdb","mysql","MariaDB"]
published: false
date: 2021-11-19T16:45:35+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 109
tistoryUrl: "https://yeolceo.tistory.com/109"
tistoryCategory: "DB/rdb"
tistoryTags: ["mysql","MariaDB","MariaDB","mysql"]
tistoryPostedAt: "2021-11-19 16:45:35"
language: ko
bloggerPostId: "1642588024917517269"
---
#### \-Environment

OS: Window 10  
DB: MariaDB 10.3.13

### \-PassWord initialize and Update

#### **1\. mysql 서비스 종료**

Window에서 '실행'을 시작합니다. (단축키 window+R)  
내용에 **services.msc를** 입력하여 실행해 주세요. 서비스 창을 켜고 mysql 서비스를 중지합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/109/img.webp)

#### **2\. mysql 실행 권한 스킵**

본인의 MySql 혹은 MariaDB의 경로의 bin 경로를 찾습니다. 그 후 cmd에서 해당 경로로 진입합니다.  
(제경우 C:\\Program Files\\MariaDB 10.3\\bin)  

```html
cd C:\Program Files\MariaDB 10.3\bin
```

첫 번째 혹은 두 번째 명령어 중 하나를 실행해줍니다. 권한을 스킵하고 실행하겠다는 의미입니다.

```html
mysqld -uroot --skip-grant-tables 
OR
mysqld --skip-grant
```

그러면 cmd 화면이 정지되면서 mysqld starting process 이와 비슷한 특정 로그가 나옵니다.

#### **3\. mysql 실행 및 비밀번호 변경**

새로운 cmd 창을 실행하고 동일한 경로에서 아래의 명령어를 실행해줍니다. 

```html
mysql -uroot mysql
```

\-그리고 update 문을 통해 원하는 비밀번호를 설정합니다. 

```html
update user set password = PASSWORD('plz input your password') WHERE user = 'root';
```

\-mysql 5.7 이후 버전일 경우( FLUSH PRIVILEGES: 기존 캐시 지우고 새 설정 적용)

```html
update user set authentication_string= PASSWORD('plz input your password') WHERE user = 'root';
 FLUSH PRIVILEGES;
```

실행 완료 로그가 나올 것입니다. 로그 중 Changed에 숫자가 생기면 잘 변경된 것입니다.  
제어판에서 mysql 서비스를 다시 시작합니다. 이때 에러가 난다면 컴퓨터를 끄고 다시 실행해주세요

#### **4\. 완료 후 테스트**

Workbanch 같은 에디터를 사용하는 유저라면 명령어와 비밀번호를 입력하여 직접 cmd에서 접근해서 실행하시면 명령어로 실행해주세요

```html
mysql -u root -p
```

**최후의 수단**

[https://goodteacher.tistory.com/291](https://goodteacher.tistory.com/291)

이 분것을 참조

성실한 코딩 하세요.
