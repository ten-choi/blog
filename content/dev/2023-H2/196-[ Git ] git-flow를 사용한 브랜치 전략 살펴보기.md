---
title: "[ Git ] git-flow를 사용한 브랜치 전략 살펴보기"
labels: ["ETC","Git","Strategy","GitHub","git-flow"]
published: false
date: 2023-12-13T17:39:13+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 196
tistoryUrl: "https://yeolceo.tistory.com/196"
tistoryCategory: "ETC/Git"
tistoryTags: ["Strategy","KR","GitHub","git-flow"]
tistoryPostedAt: "2023-12-13 17:39:13"
language: ko
bloggerPostId: "8766786131329149289"
---
![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/196/img.webp)

## **git-flow 전략을 사용하게 된 이유**

지속적인 인원증가로 인해 버전관리 전략을 대비할 필요성을 느꼈다

인원이 늘어날수록 병렬적인 업무진행을 위한 대규모에 적합한 git 전략을 준비해야 했다

그래서 러닝커브를 앞당겨 이후 자연스럽게 정착하게 하기 위해 미리 익숙해지기로 결정했다

## **git-flow 브랜치 구조**

1.  master  
    실제 제품으로 쓰이며 배포가 가능한 상태만을 관리하는 브랜치다
2.  develop  
    개발 단계에서 메인으로 관리되는 브랜치이다  
    feature와 release를 만들 때 기반이 된다
3.  feature  
    추가적인 기능을 개발할 브랜치이며 기능이 완성되면 develop에 merge 하고 불필요하게 되면 폐기한다  
    \- base가 되는 브랜치: develop  
    \- merge가 될 브랜치: develop
4.  release  
    다음버전으로 배포를 위해 최종의 테스트 및 버그수정등을 진행하는 개발용 브랜치다  
    \- base가 되는 브랜치: develop  
    \- merge가 될 브랜치: develop, master
5.  hotfix  
    배포한 버전에서 긴급하게 수정이 필요할 때 master브랜치를 base로 생성하는 브랜치다  
    \- base가 되는 브랜치: master  
    \- merge가 될 브랜치: develop, master

## Git-flow 흐름설명

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/196/img_3.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/196/img_4.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/196/img_5.webp)

#### 새로운 작업을 시작할 때

1.  GitHub 사이트의 해당 프로젝트에서 Issue를 생성한다
2.  Title과 Content에 해야 할 작업내용을 기입한다
3.  우측 사이드바에 태그를 설정한다  
    \- Assignees에 본인을 태그 한다  
    \- Labels에 Feature를 태그 한다  
    \- Project에 어느 프로젝트에서 작업하는지 태그 한다  
    \- Milestone에 PR인지 일반 Issue인지 구분하여 태그 한다
4.  생성이 완료된 경우 Issue 번호가 자동으로 생성되는데 이 번호를 feature 브랜치의 네이밍에 사용한다
5.  develop 브랜치에서 newBranch를 하고 feature와 Issue 나온 번호를 혼합해 e.g) feature-issue#3303  
    형식의 이름을 만들어주고 작업을 진행한다

하던 작업이 완료될 때

1.  GitHub 사이트의 해당 프로젝트에서 PR을 생성한다
2.  merge 될 base 브랜치에 develop을 설정하고 feature-issue#xxxx를 compare에 설정한다
3.  Title과 Content에 해야 할 작업내용을 기입한다
4.  우측 사이드바에 태그를 설정한다  
    \- Reviewers에 리뷰해 줄 사람들을 태그 한다  
    \- Assignees에 본인을 태그 한다  
    \- Labels에 Feature와 기간 내에 코드리뷰 해달라는 D-n을 태그 한다  
    \- Project에 어느 프로젝트에서 작업하는지 태그 한다  
    \- Milestone에 PR인지 일반 Issue인지 구분하여 태그 한다  
    \- Development에 본인의 Issue를 찾아 설정한다
5.  PR에 대한 코드리뷰가 진행되며 merge는 리뷰어가 진행한다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/196/img_1.webp)

#### 배포해야 할 때

1.  local에서 develop의 newBranch로 release-v \[현재버전번호+\]를 생성한다
2.  GitHub 사이트의 해당 프로젝트에서 PR을 생성한다
3.  merge 될 base 브랜치에 master를 설정하고 release를 compare에 설정한다  
    (GitHub 사이트의 해당 프로젝트 현재버전을 확인하고 브랜치의 버저닝을 진행한다)
4.  Title과 Content에 해야 할 작업내용을 기입한다
5.  우측 사이드바 태그설정  
    \- Assignees에 본인을 태그 한다  
    \- Labels에 Release를 태그 한다  
    \- Project에 어느 프로젝트에서 작업하는지 태그 한다  
    \- Milestone에 PR인지 일반 Issue인지 구분하여 태그 한다  

6.  release브랜치가 최종으로 확인이 끝나면 GitHub 사이트에서 merge를 한다  
    GitAction을 통해 자동으로 배포된다
7.  release브랜치에 변경사항이 있다면 develop브랜치에도 merge 하고 release브랜치를 삭제한다

release version 표기 설명

-   Release Number: 1로 시작하며 해당 프로젝트에 극심한 변화가 생길 경우 숫자를 1 올린다
-   Major Number: 0으로 시작하며 주요 기능이 추가되거나 변경되었을 때 숫자를 1 올린다
-   Minor Number: 0으로 시작해며 버그 수정 등 미미한 변화가 발생하면 숫자를 1 올린다

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/196/img_2.webp)

#### 핫픽스를 해야 할 때

1.  local에서 develop의 newBranch로 hotfix-\[현재버전번호\]를 생성한다
2.  수정해야 할 부분을 수정한다
3.  git 사이트에서 pr을 생성
4.  머지될 base 브랜치에 master을 설정하고 hotfix-v1.23.4를 compare에 설정
5.  title에 어떤 작업이 pr 되는지 기입
6.  content에 내용설명
7.  우측 사이드바 태그설정  
    Assignees에 본인 태그  
    Labels에 branch의 속성 태그 e.g) Hotfix  
    Project에 어느 프로젝트인지 태그  
    milestone에 pr인지 issue인지 구분하여 태그
8.  최종테스트가 끝나면 github 사이트를 통해 머지
9.  수정사항이 있었다면 develop에도 머지하고 해당 브랜치 delete
10.  GitAction을 통해 prod로 배포가 진행됨

## 배포이후 할 일

릴리즈 노트에 작업시간, 작업목록, 버전등 수정해서 슬랙등의 공유메신저에 팀원이 볼 수 있게 글을 올립니다

전략에 대해서는 이후 다시 한번 수정하여 글을 작성해보려 한다
