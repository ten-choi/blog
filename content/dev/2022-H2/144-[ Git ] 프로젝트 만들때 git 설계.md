---
title: "[ Git ] 프로젝트 만들때 git 설계"
labels: ["ETC","Git"]
published: false
date: 2022-08-22T17:38:50+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 144
tistoryUrl: "https://yeolceo.tistory.com/144"
tistoryCategory: "ETC/Git"
tistoryTags: ["git","git","git"]
tistoryPostedAt: "2022-08-22 17:38:50"
language: ko
bloggerPostId: "6267284894056286048"
---
#### ? **환경** 

#### ? **개요**

git을 어떻게 사용하면 가독성, 효율성 등을 고려하며 설계하기!

#### ? **목차**

-   git 초기 세팅
-   git flow 브랜치
-   issue, bug, pr

## **\- git 초기 세팅**

1.  git 프로젝트 생성하기
2.  해당 git issue template bug랑 feature 만들기 (이미지 참조)
3.  git tool 통해 clone 받기  
    계정이 2개일 경우 설정에서 추가(저는 git fork 툴 사용)
4.  브랜 치명이 prod인 브랜치 생성하고 그 브랜치 사용  
    나중에 dev, feature 브랜치를 추가 , staging는 optional 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/144/img_1.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/144/img_2.webp)

## **\- git flow 브랜치**

아래가 사용할 브랜치들입니다. 필요한 경우 늘리거나 제거합니다.  

1.  prod: 실제 배포되어있는 서비스 브랜치
2.  dev: feature에서 pr 받을 배포 이전 단계의 테스트 브랜치
3.  feature-issue#1: 새로운 기능을 추가할 때 git의 issue number를 추가하여 생성할 브랜치
4.  hotfix-issue#1: prod에서 문제가 생겼을 경우 생성할 브랜치
5.  staging: prod와 가장 흡사한 환경에서 테스트하는 브랜치  
    (서드파티에서 prod와 dev의 리턴 값이 다르거나 dev에서만 테스트가 가능할 경우 의미가 퇴색될 수 있는 브랜치)

feature -> dev, hotfix -> prod 순서로 prod가 가장 상위의 브랜치입니다.  
하위에서 상위로 pr을 날리고 테스트하고 그위로 pr을 날리는 구조이며 hotfix나 dev에서 일부 수정할 경우  
rebase를 통해 기존 브랜치의 base를 변경된 값으로 따라갑니다.

## **\- issue, bug, pr**

issue나 bug, pr 등의 문서적 정리는 해당 프로젝트의 git 홈페이지에서 관리합니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/144/img_3.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/144/img_4.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/144/img.webp)

이슈의 경우에는 생성할 때 생기는 number를 늘 활용해줍니다.

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
