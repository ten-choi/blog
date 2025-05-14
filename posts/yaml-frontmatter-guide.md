---
title: "YAML Front Matter로 Dev.to 게시물 작성하기"
published: false
description: "Dev.to 게시물을 위한 YAML Front Matter 가이드와 예제"
tags: devto, markdown, yaml, blogging
cover_image: https://images.unsplash.com/photo-1517694712202-14dd9538aa97
series: "Dev.to 게시 가이드"
---

# YAML Front Matter로 Dev.to 게시물 작성하기

이 게시물에서는 Dev.to에 글을 쓸 때 YAML Front Matter를 어떻게 사용하는지 설명합니다.

## YAML Front Matter란?

YAML Front Matter는 마크다운 파일 맨 위에 위치하는 메타데이터 블록입니다. 이 블록은 `---` 구분자 사이에 작성되며, 게시물의 제목, 설명, 태그 등 다양한 속성을 정의할 수 있습니다.

## 기본 구조

기본적인 YAML Front Matter 구조는 다음과 같습니다:

```yaml
---
title: "게시물 제목"
published: false
description: "게시물 설명"
tags: tag1, tag2, tag3
---
```

## 지원되는 속성들

Dev.to에서 지원하는 주요 Front Matter 속성들:

### 필수 속성

- `title`: 게시물 제목

### 선택적 속성

- `published`: 게시 여부 (true/false)
- `description`: 게시물 요약 설명
- `tags`: 콤마로 구분된 태그 목록
- `cover_image`: 게시물 커버 이미지 URL
- `series`: 게시물이 속한 시리즈 이름
- `canonical_url`: 원본 콘텐츠 URL (크로스 포스팅 시 사용)
- `date`: 게시물 날짜 (YYYY-MM-DD 형식)

## 예제

다음은 완전한 YAML Front Matter 예제입니다:

```yaml
---
title: "JavaScript 비동기 프로그래밍 마스터하기"
published: true
description: "Promise, async/await을 사용한 JavaScript 비동기 프로그래밍 가이드"
tags: javascript, webdev, tutorial, beginners
cover_image: https://example.com/cover-image.jpg
series: "JavaScript 마스터 시리즈"
canonical_url: https://my-blog.com/original-post
date: 2025-05-14
---
```

## 팁과 모범 사례

1. **태그는 4개 이하로 유지하세요**: Dev.to는 게시물당 최대 4개의 태그를 표시합니다.
2. **커버 이미지 사용하기**: 커버 이미지를 사용하면 게시물이 더 눈에 띄게 됩니다.
3. **시리즈 만들기**: 관련 게시물들을 시리즈로 묶으면 독자들이 콘텐츠를 쉽게 따라갈 수 있습니다.
4. **초안으로 시작하기**: `published: false`로 설정하면 게시물을 초안으로 저장하고 나중에 검토한 후 게시할 수 있습니다.

## GitHub 통합 시 Front Matter 활용

GitHub 저장소와 Dev.to를 연동했다면, 저장소에 마크다운 파일을 추가할 때 위에서 설명한 Front Matter를 포함시켜야 합니다. GitHub에 푸시한 후 Dev.to는 이 메타데이터를 읽고 게시물을 적절하게 형식화합니다.

## 결론

YAML Front Matter는 Dev.to 게시물의 메타데이터를 관리하는 강력한 방법입니다. 이를 활용하면 게시물의 모양과 분류 방식을 더 세밀하게 제어할 수 있습니다.

궁금한 점이나 의견이 있으시면 댓글로 알려주세요!
