# DEV.to 블로그 배포 도구

TypeScript로 개발된 이 도구는 마크다운 파일을 DEV.to에 손쉽게 게시하고 관리할 수 있도록 도와줍니다.

## 🚀 설치 및 설정

### 1. 저장소 클론하기

```bash
git clone https://github.com/yourusername/blog.git
cd blog
```

### 2. 의존성 설치하기

```bash
npm install
```

### 3. DEV.to API 토큰 설정하기

`.env` 파일을 생성하고 DEV.to API 토큰을 설정합니다:

```
DEVTO_TOKEN_PROD=your_api_token_here
```

API 토큰은 [DEV.to 설정 페이지](https://dev.to/settings/account)에서 발급받을 수 있습니다.

### 4. TypeScript 코드 빌드하기

```bash
npm run build
```

## 📝 블로그 게시물 작성하기

### 1. 새 게시물 생성

`posts` 디렉토리에 마크다운(`.md`) 파일을 생성하세요. 각 파일은 YAML Front Matter 형식으로 메타데이터를 포함해야 합니다:

```markdown
---
title: 게시물 제목
published: false # true로 설정하면 즉시 공개됩니다
description: 게시물 설명 # 검색 결과에 표시됩니다
tags: tag1, tag2, tag3 # 최대 4개까지 가능합니다
cover_image: https://example.com/your-image.jpg # 대표 이미지
series: 시리즈 이름 # 시리즈물인 경우 설정
---

# 여기서부터 게시물 내용을 작성하세요

마크다운 문법으로 자유롭게 작성하세요...
```

### 2. 게시물 유효성 검사

작성한 게시물이 올바른 형식인지 검사합니다:

```bash
# 모든 게시물 검사
npm run validate

# 특정 게시물만 검사
npm run validate posts/my-post.md
```

### 3. DEV.to에 게시하기

API 토큰을 사용하여 DEV.to에 직접 게시합니다:

```bash
# 모든 게시물 게시
npm run publish

# 특정 게시물만 게시
npm run publish:single posts/my-post.md
```

게시 결과로 DEV.to 게시물 URL이 표시됩니다.

## ⚙️ 게시물 관리

### 게시 상태 설정

Front Matter의 `published` 속성으로 게시 상태를 제어할 수 있습니다:

- `published: false`: DEV.to에 초안으로 저장됩니다. 다른 사용자에게 보이지 않습니다.
- `published: true`: 게시와 동시에 즉시 공개됩니다.

### 게시물 업데이트

이미 게시된 게시물을 수정하려면:

1. 마크다운 파일을 수정합니다
2. `npm run publish:single posts/수정된-파일.md` 명령으로 업데이트합니다

DEV.to는 제목을 기준으로 게시물을 식별하므로, 제목을 변경하면 새 게시물로 인식될 수 있습니다.

## 💡 팁과 트릭

- **태그**: 태그는 쉼표로 구분하며, 최대 4개까지 사용할 수 있습니다
- **대표 이미지**: `cover_image` 속성에 이미지 URL을 설정하면 게시물 상단에 표시됩니다
- **시리즈**: 연결된 게시물은 동일한 `series` 값을 사용하여 시리즈로 묶을 수 있습니다
- **마크다운 스타일링**: DEV.to는 마크다운과 일부 HTML 태그를 지원합니다
- **표와 코드 블록**: 표와 코드 블록은 DEV.to에서 깔끔하게 렌더링됩니다

## 🛠️ 개발자 정보

이 프로젝트는 TypeScript로 개발되었으며, DEV.to API를 활용하여 블로그 게시물을 자동화된 방식으로 관리합니다.

### 프로젝트 구조

```
/
├── posts/             # 마크다운 게시물 저장소
├── src/               # TypeScript 소스 코드
│   ├── publish.ts     # 게시물 배포 스크립트
│   ├── validate.ts    # 게시물 유효성 검사
│   └── types/         # 타입 정의 파일
├── dist/              # 컴파일된 JS 파일 (빌드 후 생성)
├── .env               # API 토큰 환경변수
├── tsconfig.json      # TypeScript 설정
└── package.json       # 프로젝트 의존성 및 스크립트
```

### 명령어 모음

```bash
# 의존성 설치
npm install

# TypeScript 컴파일
npm run build

# 게시물 유효성 검사
npm run validate

# 게시물 배포
npm run publish

# 특정 게시물만 배포
npm run publish:single posts/your-post.md
```

## 📚 더 알아보기

- [DEV.to API 문서](https://developers.forem.com/api)
- [마크다운 작성 가이드](YAML_GUIDE.md)
- [GitHub 저장소 연동 방법](GITHUB_INTEGRATION.md) (선택적 대체 방법)
