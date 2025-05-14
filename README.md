# DEV.to 블로그 저장소

이 저장소는 DEV.to 블로그 게시물을 관리하고 배포하는 데 도움을 줍니다.

## 설정 방법 (2가지 방식)

### 1. GitHub 저장소 직접 연동 방식 (API 키 불필요)

1. dev.to에 로그인합니다
2. [계정 설정 페이지](https://dev.to/settings/extensions)로 이동합니다
3. 'DEV Community 🔑' 섹션에서 'Github'를 찾습니다
4. 'Connect Github to DEV'를 클릭합니다
5. 계정을 연결하고 이 저장소에 접근 권한을 허용합니다
6. 이제 dev.to에서 '새 게시물 작성' 페이지로 이동하여 'Publish from Github'을 선택합니다
7. 연결된 저장소 목록에서 이 저장소를 선택합니다
8. '/posts' 폴더의 마크다운 파일이 게시물로 표시됩니다
9. 게시하려는 파일을 선택하고 'Import'를 클릭합니다

### 2. API 연동 방식

1. 이 저장소를 클론합니다
2. 의존성 설치: `npm install`
3. DEV.to API 키로 `.env` 파일을 생성합니다:
   ```
   DEVTO_API_KEY=your_api_key_here
   ```
   API 키는 [DEV.to 설정](https://dev.to/settings/account)에서 얻을 수 있습니다

## 사용 방법

### 새 블로그 게시물 작성하기

`posts` 디렉토리에 새 마크다운 파일을 생성합니다. 각 파일은 다음과 같은 형식의 Front Matter가 포함되어야 합니다:

```markdown
---
title: 블로그 게시물 제목
published: false
description: 게시물에 대한 간단한 설명
tags: tag1, tag2, tag3
cover_image: https://example.com/your-image.jpg
series: 시리즈 이름 (선택사항)
---

게시물 내용...
```

### DEV.to에 게시하기

#### GitHub 연동 방식

GitHub에 변경사항을 커밋하고 푸시하면, dev.to의 'Publish from Github' 기능을 통해 게시물을 가져올 수 있습니다.

#### API 연동 방식

모든 블로그 게시물 게시:

```
npm run publish
```

특정 블로그 게시물 게시:

```
npm run publish:single posts/your-post-file.md
```

## 게시물 상태

- `published: false` - 초안으로 저장
- `published: true` - 즉시 게시

## 팁

- 태그는 쉼표로 구분됩니다
- API 키는 비공개로 유지하세요
- 서식 지정에는 마크다운을 사용하세요
