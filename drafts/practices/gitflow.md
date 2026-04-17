---
title: "GitFlow 워크플로우 전략 가이드"
date: 2023-06-18
categories: ["개발 방법론", "버전 관리"]
tags: ["git", "gitflow", "협업", "워크플로우", "브랜칭 전략"]
description: "효율적인 소프트웨어 개발과 협업을 위한 GitFlow 브랜칭 전략의 완전한 가이드"
---

# GitFlow 워크플로우 전략 가이드

## 목차

- [GitFlow 워크플로우 전략 가이드](#gitflow-워크플로우-전략-가이드)
  - [목차](#목차)
  - [GitFlow 소개](#gitflow-소개)
  - [GitFlow 브랜치 구조](#gitflow-브랜치-구조)
  - [주요 브랜치](#주요-브랜치)
    - [master / main 브랜치](#master--main-브랜치)
    - [develop 브랜치](#develop-브랜치)
  - [보조 브랜치](#보조-브랜치)
    - [feature 브랜치](#feature-브랜치)
    - [release 브랜치](#release-브랜치)
    - [hotfix 브랜치](#hotfix-브랜치)
  - [GitFlow 워크플로우 실제 적용](#gitflow-워크플로우-실제-적용)
  - [Git 명령어로 보는 GitFlow](#git-명령어로-보는-gitflow)
    - [1. 프로젝트 초기화](#1-프로젝트-초기화)
    - [2. 기능 개발](#2-기능-개발)
    - [3. 릴리스 준비](#3-릴리스-준비)
    - [4. 긴급 수정](#4-긴급-수정)
  - [GitFlow 확장 도구](#gitflow-확장-도구)
    - [Git Flow CLI 확장](#git-flow-cli-확장)
    - [IDE 통합](#ide-통합)
  - [GitFlow 장단점](#gitflow-장단점)
    - [장점](#장점)
    - [단점](#단점)
  - [자주 묻는 질문 (FAQ)](#자주-묻는-질문-faq)
    - [Q1. GitHub Flow와 GitFlow의 차이점은 무엇인가요?](#q1-github-flow와-gitflow의-차이점은-무엇인가요)
    - [Q2. 소규모 프로젝트에도 GitFlow를 사용해야 할까요?](#q2-소규모-프로젝트에도-gitflow를-사용해야-할까요)
    - [Q3. release 브랜치에서 새로운 기능을 추가해도 될까요?](#q3-release-브랜치에서-새로운-기능을-추가해도-될까요)
    - [Q4. GitFlow와 CI/CD는 어떻게 통합하나요?](#q4-gitflow와-cicd는-어떻게-통합하나요)
  - [참고 자료](#참고-자료)

## GitFlow 소개

GitFlow는 Vincent Driessen이 2010년에 제안한 Git 브랜칭 모델로, 체계적이고 예측 가능한 방식으로 소프트웨어를 개발하고 배포할 수 있는 워크플로우입니다. 이 모델은 특히 여러 개발자가 동시에 작업하는 대규모 프로젝트에서 효과적입니다.

GitFlow는 팀이 기능 개발, 릴리스 준비, 긴급 수정 등을 병렬적으로 진행할 수 있게 해주며, 각 작업 영역을 명확히 분리하여 운영 환경의 안정성을 보장합니다.

## GitFlow 브랜치 구조

GitFlow 워크플로우는 다음과 같은 브랜치 구조를 가집니다:

![GitFlow 브랜치 구조](https://nvie.com/img/git-model@2x.png)

## 주요 브랜치

GitFlow에서는 두 개의 주요 브랜치(무기한 지속되는 브랜치)가 있습니다:

### master / main 브랜치

`master` (또는 `main`) 브랜치는 항상 프로덕션 준비 상태를 유지하는 브랜치입니다.

- 이 브랜치의 모든 코드는 테스트되고 배포 가능한 상태여야 합니다
- 직접적인 커밋은 허용되지 않으며, 모든 변경은 다른 브랜치를 통해 병합됩니다
- 각 릴리스는 태그로 표시되어 버전 추적이 용이합니다

```bash
# master 브랜치에 태그 생성 예시
git tag -a v1.0.0 -m "버전 1.0.0 릴리스"
```

### develop 브랜치

`develop` 브랜치는 다음 릴리스를 위한 개발 작업이 진행되는 브랜치입니다.

- 모든 새로운 개발 작업의 기준점이 됩니다
- 완성된 기능들이 여기에 통합됩니다
- 다음 릴리스를 준비하는 과정에서 이 브랜치가 `release` 브랜치로 분기됩니다

```bash
# develop 브랜치 생성 예시
git checkout -b develop master
```

## 보조 브랜치

세 가지 유형의 보조 브랜치가 있으며, 각각 특정 목적을 가집니다:

### feature 브랜치

`feature` 브랜치는 새로운 기능 개발이나 버그 수정을 위해 생성됩니다.

- 항상 `develop` 브랜치에서 분기합니다
- 기능 개발이 완료되면 다시 `develop` 브랜치로 병합됩니다
- 명명 규칙: `feature/기능명`

```bash
# 새로운 feature 브랜치 생성
git checkout -b feature/user-authentication develop

# 기능 개발 후 develop에 병합
git checkout develop
git merge --no-ff feature/user-authentication
git branch -d feature/user-authentication
```

### release 브랜치

`release` 브랜치는 새 버전 출시를 준비하기 위해 생성됩니다.

- `develop` 브랜치에서 분기하여 생성합니다
- 새 기능은 추가하지 않고, 버그 수정, 문서화, 릴리스 준비 작업만 수행합니다
- 준비가 완료되면 `master`와 `develop` 브랜치 모두에 병합됩니다
- 명명 규칙: `release/버전번호`

```bash
# 새로운 release 브랜치 생성
git checkout -b release/1.0.0 develop

# 릴리스 준비 작업 후
# 1. master에 병합
git checkout master
git merge --no-ff release/1.0.0
git tag -a v1.0.0 -m "버전 1.0.0"

# 2. develop에도 변경사항 반영
git checkout develop
git merge --no-ff release/1.0.0

# 3. release 브랜치 삭제
git branch -d release/1.0.0
```

### hotfix 브랜치

`hotfix` 브랜치는 프로덕션 환경에서 발생한 긴급 문제를 수정하기 위해 생성됩니다.

- `master` 브랜치에서 직접 분기합니다
- 문제 해결 후 `master`와 `develop` 브랜치 모두에 병합됩니다
- 명명 규칙: `hotfix/버전번호` 또는 `hotfix/문제명`

```bash
# hotfix 브랜치 생성
git checkout -b hotfix/1.0.1 master

# 긴급 수정 후
# 1. master에 병합
git checkout master
git merge --no-ff hotfix/1.0.1
git tag -a v1.0.1 -m "버전 1.0.1"

# 2. develop에도 병합
git checkout develop
git merge --no-ff hotfix/1.0.1

# 3. hotfix 브랜치 삭제
git branch -d hotfix/1.0.1
```

## GitFlow 워크플로우 실제 적용

GitFlow 워크플로우의 일반적인 진행 과정은 다음과 같습니다:

1. **프로젝트 초기화**:

   - `master` 브랜치 생성
   - `develop` 브랜치 생성

2. **기능 개발**:

   - `feature` 브랜치 생성
   - 기능 개발 및 테스트
   - `develop` 브랜치에 병합

3. **릴리스 준비**:

   - `release` 브랜치 생성
   - QA 테스트 및 버그 수정
   - `master`와 `develop` 브랜치에 병합

4. **긴급 수정**:
   - `hotfix` 브랜치 생성
   - 문제 해결
   - `master`와 `develop` 브랜치에 병합

## Git 명령어로 보는 GitFlow

아래는 GitFlow 워크플로우의 주요 작업을 Git 명령어로 표현한 것입니다:

### 1. 프로젝트 초기화

```bash
# 저장소 초기화
git init

# master 브랜치 첫 커밋
git add .
git commit -m "초기 커밋"

# develop 브랜치 생성
git checkout -b develop master
```

### 2. 기능 개발

```bash
# feature 브랜치 생성
git checkout -b feature/login develop

# 작업 커밋
git add .
git commit -m "로그인 기능 구현"

# develop에 병합 (--no-ff: fast-forward 없이 병합)
git checkout develop
git merge --no-ff feature/login
git branch -d feature/login
```

### 3. 릴리스 준비

```bash
# release 브랜치 생성
git checkout -b release/1.0.0 develop

# 버그 수정 등의 작업
git add .
git commit -m "릴리스 준비: 버전 정보 업데이트"

# master에 병합
git checkout master
git merge --no-ff release/1.0.0
git tag -a v1.0.0 -m "버전 1.0.0 릴리스"

# develop에도 병합
git checkout develop
git merge --no-ff release/1.0.0

# release 브랜치 삭제
git branch -d release/1.0.0
```

### 4. 긴급 수정

```bash
# hotfix 브랜치 생성
git checkout -b hotfix/1.0.1 master

# 긴급 수정 작업
git add .
git commit -m "중요 보안 취약점 수정"

# master에 병합
git checkout master
git merge --no-ff hotfix/1.0.1
git tag -a v1.0.1 -m "버전 1.0.1 릴리스"

# develop에도 병합
git checkout develop
git merge --no-ff hotfix/1.0.1

# hotfix 브랜치 삭제
git branch -d hotfix/1.0.1
```

## GitFlow 확장 도구

GitFlow를 더 쉽게 적용할 수 있는 도구들이 있습니다:

### Git Flow CLI 확장

```bash
# macOS (Homebrew)
brew install git-flow

# Linux
apt-get install git-flow  # Debian/Ubuntu
yum install git-flow      # CentOS/RHEL

# 프로젝트 초기화
git flow init

# 기능 개발
git flow feature start 로그인
git flow feature finish 로그인

# 릴리스 준비
git flow release start 1.0.0
git flow release finish 1.0.0

# 긴급 수정
git flow hotfix start 1.0.1
git flow hotfix finish 1.0.1
```

### IDE 통합

대부분의 현대적인 IDE는 GitFlow 워크플로우를 지원하는 플러그인이나 내장 기능을 제공합니다:

- **IntelliJ IDEA / WebStorm**: Git Flow Integration 플러그인
- **Visual Studio Code**: GitFlow 확장 프로그램
- **SourceTree**: 내장 GitFlow 지원

## GitFlow 장단점

### 장점

- **체계적인 구조**: 명확한 브랜치 구조와 워크플로우 제공
- **병렬 개발**: 다양한 기능과 버전을 동시에 개발 가능
- **안정적인 프로덕션**: `master` 브랜치의 코드는 항상 안정적
- **버전 관리**: 태그를 통한 명확한 버전 관리

### 단점

- **복잡성**: 작은 프로젝트에는 과도하게 복잡할 수 있음
- **오버헤드**: 많은 브랜치와 병합 과정으로 인한 관리 오버헤드
- **지속적 통합/배포(CI/CD)와의 충돌**: 현대적인 CI/CD 파이프라인에서는 다소 불필요한 단계가 있을 수 있음

## 자주 묻는 질문 (FAQ)

### Q1. GitHub Flow와 GitFlow의 차이점은 무엇인가요?

GitFlow는 많은 브랜치와 엄격한 워크플로우를 가진 복잡한 모델인 반면, GitHub Flow는 단순한 `master` 브랜치와 기능 브랜치만을 사용하는 더 간소화된 모델입니다. GitHub Flow는 지속적 배포에 더 적합하며, GitFlow는 특정 릴리스 사이클을 가진 프로젝트에 더 적합합니다.

### Q2. 소규모 프로젝트에도 GitFlow를 사용해야 할까요?

소규모 프로젝트나 빠른 개발 사이클을 가진 프로젝트에서는 GitFlow가 과도한 오버헤드를 발생시킬 수 있습니다. 이런 경우 GitHub Flow나 더 단순화된 Trunk-Based Development를 고려해볼 수 있습니다.

### Q3. release 브랜치에서 새로운 기능을 추가해도 될까요?

GitFlow 원칙에 따르면, `release` 브랜치는 버그 수정과 릴리스 준비 작업만을 위한 것으로, 새로운 기능 추가는 지양해야 합니다. 새 기능은 `develop` 브랜치에서 개발하고 다음 릴리스에 포함시키는 것이 좋습니다.

### Q4. GitFlow와 CI/CD는 어떻게 통합하나요?

CI/CD와 GitFlow를 함께 사용할 때는 다음과 같은 전략을 고려할 수 있습니다:

- `develop` 브랜치에 대한 지속적 통합
- `release` 브랜치에 대한 자동화된 테스트 및 스테이징 환경 배포
- `master` 브랜치에 대한 프로덕션 자동 배포 (또는 수동 승인 후 배포)

---

GitFlow는 일관되고 예측 가능한 개발 및 배포 프로세스를 제공하지만, 프로젝트의 규모, 팀 구성, 배포 빈도 등을 고려하여 적용 여부를 결정해야 합니다. 대규모 프로젝트나 엄격한 릴리스 관리가 필요한 경우 GitFlow는 매우 효과적인 브랜칭 전략이 될 수 있습니다.

## 참고 자료

- [A successful Git branching model](https://nvie.com/posts/a-successful-git-branching-model/) - Vincent Driessen의 원본 GitFlow 아티클
- [Atlassian Git Tutorial - Comparing Workflows](https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow) - Atlassian의 GitFlow 워크플로우 가이드
- [GitHub Flow](https://docs.github.com/en/get-started/using-github/github-flow) - 대안적인 GitHub Flow 설명
