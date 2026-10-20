---
title: "[ Spring ] spring batch 란"
labels: []
published: false
date: 2023-12-07T20:22:24+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 207
tistoryUrl: "https://yeolceo.tistory.com/207"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2023-12-07 20:22:24"
language: ko
bloggerPostId: "8333892284557751566"
---
Spring Batch에는 굉장히 많은 설정과 기능들이 존재합니다. 해당 포스팅에서는 기초적인 Spring Batch에 대해서 설명하고 사용하는 예제에 대해서 설명을 하려고 합니다. Spring Batch를 사용하지 않았던 사람도 해당 포스팅을 보고 간단하게 Spring Batch를 사용할 수 있도록 하며 다양한 설정 및 추가적인 기능들은 Project를 진행하며 알아보고 공부하면 좋을 것 같습니다.

# **Spring Batch**

Spring Batch는 로깅/추적, 트랜잭션 관리, 작업 처리 통계, 작업 재시작, 건너뛰기, 리소스 관리 등 대용량 레코드 처리에 필수적인 기능을 제공합니다. 또한 최적화 및 파티셔닝 기술을 통해 대용량 및 고성능 배치 작업을 가능하게 하는 고급 기술 서비스 및 기능을 제공합니다.

Spring Batch에서 배치가 실패하여 작업 재시작을 하게 된다면 처음부터가 아닌 실패한 지점부터 실행을 하게 됩니다.

또한 중복 실행을 막기 위해 성공한 이력이 있는 Batch는 동일한 Parameters로 실행 시 Exception이 발생하게 됩니다.
