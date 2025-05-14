# GitHub과 DEV.to 직접 연동하기

이 문서는 API 키를 사용하지 않고 GitHub 저장소와 DEV.to를 직접 연동하는 방법을 자세히 설명합니다.

## 연동 방법

### 1단계: GitHub 계정 연결하기

1. [DEV.to](https://dev.to)에 로그인합니다.
2. 우측 상단의 프로필 이미지를 클릭하고 `Settings`로 이동합니다.
3. 왼쪽 메뉴에서 `Extensions`를 선택합니다.
4. 'DEV Community 🔑' 섹션에서 'Github'를 찾고 `Connect Github to DEV`를 클릭합니다.
5. GitHub 인증 과정을 완료하고 필요한 권한을 허용합니다.

![GitHub 연결 화면](https://dev-to-uploads.s3.amazonaws.com/i/9gj2sbxh37l9x9dt6jga.png)

### 2단계: 저장소에서 게시물 가져오기

1. DEV.to에서 `Write a post` 버튼을 클릭하여 새 게시물 작성 페이지로 이동합니다.
2. 페이지 상단에서 `Publish from Github` 탭을 선택합니다.
3. 연결된 GitHub 저장소 목록이 표시됩니다. 이 블로그 저장소를 선택합니다.
4. `/posts` 폴더의 마크다운 파일이 목록으로 표시됩니다.
5. 가져오려는 파일을 선택하고 `Import`를 클릭합니다.

![GitHub에서 게시물 가져오기](https://dev-to-uploads.s3.amazonaws.com/i/5fdt993plh7yyec2c5dv.jpg)

## 파일 구조 및 형식

GitHub 저장소에서 DEV.to로 게시물을 가져올 때, 다음 사항에 주의하세요:

### 기본 경로

DEV.to는 기본적으로 저장소의 루트 디렉토리에서 마크다운 파일을 찾습니다. 그러나 이 저장소에서는 `/posts` 디렉토리에 마크다운 파일을 저장합니다.

### Front Matter 형식

각 마크다운 파일은 다음 형식의 Front Matter로 시작해야 합니다:

```markdown
---
title: 게시물 제목
published: false # true로 설정하면 즉시 공개됩니다
description: 게시물 설명
tags: tag1, tag2, tag3
cover_image: https://example.com/image.jpg # 선택 사항
series: 시리즈 이름 # 선택 사항
---

게시물 내용...
```

## 동기화 작동 방식

1. GitHub 저장소의 마크다운 파일을 수정하면, 변경 사항이 자동으로 DEV.to에 반영되지 않습니다.
2. 변경 사항을 반영하려면, DEV.to의 `Publish from Github` 기능을 통해 게시물을 다시 가져와야 합니다.
3. DEV.to에서 직접 수정한 게시물은 GitHub 저장소에 반영되지 않습니다. 이것은 단방향 동기화입니다.

## 팁

- 저장소에 새 마크다운 파일을 추가하면, DEV.to의 `Publish from Github` 목록에 새 파일이 표시됩니다.
- Front Matter의 `published: true`로 설정하면 DEV.to에서 가져온 후 즉시 공개됩니다.
- Front Matter의 `published: false`로 설정하면 DEV.to에서 초안으로 저장됩니다.
- 이미지는 DEV.to에 직접 업로드하거나, 외부 URL을 사용할 수 있습니다.

## 문제 해결

- 게시물이 목록에 표시되지 않는 경우, 마크다운 파일의 Front Matter 형식이 올바른지 확인하세요.
- GitHub 연결에 문제가 있는 경우, DEV.to 설정에서 연결을 해제하고 다시 연결해 보세요.
- DEV.to의 게시물 가져오기 기능에 대한 자세한 내용은 [공식 문서](https://dev.to/p/editor_guide)를 참조하세요.
