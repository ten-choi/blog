---
title: "MariaDB Replication 설정 및 활용 (how to use database replication on MariaDB)"
labels: ["Cloud","azure"]
published: false
date: 2022-01-25T15:31:01+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 122
tistoryUrl: "https://yeolceo.tistory.com/122"
tistoryCategory: "Cloud/azure"
tistoryTags: ["azure","azure","azure","azure","azure"]
tistoryPostedAt: "2022-01-25 15:31:01"
language: ko
bloggerPostId: "5650847705795302068"
retitled: true
---
#### 환경

Linux (Redhat or centos) 2대

#### 개요

MariaDB의 replication 기능을 통해 2대 이상의 db에 데이터를 복제하여 저장하는 방식입니다.

master와 slave로 나누는 작업을 진행합니다.  
실시간으로 백업이 가능하다는 의미로 한쪽이 문제가 생겼을때 대처가능.

db의 부하를  분산시킬수 있습니다.

양똑다 액티브하게 사용할거기때문에 서로에게 마스터 슬레이브 설정을 걸것이고 

#### 목차

-   2개의 서버에 마리아db 확인
-   가
-   부하분산 장치(loadBalancer) 만들기
-   lb를 위한 vm 2대 만들기
-   각 서버에 접속할 httpd 생성
-   lb test

## **[https://puham.tistory.com/71](https://puham.tistory.com/71) 이거보고 만들기**

## **\- 마리아 db설치**

아래의 명령어를 통해 MariaDB를 설치해주세요. 또한 버전을 확인하여 잘 설치되있는지 확인합니다.

설치링크 맞는버전 설치 yum 저장소 설정 가져오기 ㄴㅇㄹㄴㅇㄹ

ㄴㅇㄹ

[https://mariadb.org/download/?t=repo-config](https://mariadb.org/download/?t=repo-config)  

```cs
[user]#sudo yum install mariadb -y
[user]#sudo mariadb --version
```

ㄴㅇㄹ

## **\- 마리아 db conf 셋팅**

mariadb를 통해 정보를 수정

```cs
[user]# vi /etc/my.conf
```

만들기를 누르면 아래와 소스가 최초의 기본설정입니다.

```vala
#
# This group is read both by the client and the server
# use it for options that affect everything
#
[client-server]

#
# include *.cnf from the config directory
#
!includedir /etc/my.cnf.d
```

리소스 그룹은 원하는 명칭을 만들어주세요.

**mysql-bin**은 binary log의 파일명을 의미한다.

**server-id**는 master와 slave의 값만 다르면 된다. 아무 숫자나 사용 가능.

**binlog\_format**는 유형을 선택한다.(STATEMENT, ROW, MIXED 중 선택)

-   **STATEMENT** \- SQL문을 복사
-   **ROW** \- 변경된 row만 복사
-   **MIXED** \- 두 가지 방식을 섞어서 복사

**expire\_logs\_days**는 보관기간을 설정한다.

-   binarylog = binlog
-   mysql(maria DB)에서 발생하는 모든 내역들이 기록되는 파일이다.
-   binay log는 default는 비활성되어있는데, 이를 활성화시켜야 한다.

아래의 명령어를 통해 마리아 db를 재시작 합니다.

```cs
[user]# sudo systemctl restart mysqld
```

그리고 명령어를 통해 mariadb에 접속해줍니다. 

```cs
[user]# sudo mysql -u root -p
```

유저를 만들어줍니다. 

```routeros
[user]# create user 'repli'@'222.222.222.222' identified by 'password';
```

asdf

## **\- 마리아 db 설계**

mariadb 

리소스 그룹은 원하는 명칭을 만들어주세요.

따라오느라 고생하셨습니다. 성실한 코딩 하세요.

## **\- 마리아 db 설계**

mariadb 

리소스 그룹은 원하는 명칭을 만들어주세요.

따라오느라 고생하셨습니다. 성실한 코딩 하세요.
