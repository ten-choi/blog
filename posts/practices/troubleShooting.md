---
title: MySQL Performance Optimization
published: false
description: Testing a post in a category subfolder
tags: database, rdb, mysql, optimization
cover_image: https://example.com/your-cover-image.jpg
series: Testing Series
---

# trobleshooting

이러한 구조로 이어진다

최근에 나의 경우에는

spring di에서 문제가 있었다

jenkins를 사용한 ci cd를 구축하는데 레거시 파일의 자사 솔루션에서 git lab과 jenkins를 이용한 cicd를 하는데 기존기능을 일부 가져와야 하는게 포인트다

그리고 cicd를 완성했는데 deploy부분에서 실행이 안되는 부분이 있엇다 local에서는 기동에 문제가없었기에 환경에 문제가 있나 계속 살펴보았다

아래와같은 문제가 있었고 절차대로 해결하였다
트러블 슈팅을 규칙안에서 실행할수록 시간이 절약되기때문에 낭비를 막는다는 점에서 이러한 진행방식은 굉장히 중요하다

1. 에러확인
2. 로그확인
3. 로그를 보니 특정값이 null이라고 나옴
4. 실행이나 환경에서 뭔가 설정이 부족한건지 확인ㅇ
5. 아니여서 내부적인 문제라고 판단 후 내부 살펴보니 특정 라이브러리가 실행이 안되는걸확인
6. 해당 lib를 확인결과 springDI가 되지않았다고 판단
7. 해당 부서에 이부분을 교차검증하여 이전부터 문제가 있던부분으로 문제확인
