# Dev.to 블로그 게시물 검증 및 YAML Front Matter 가이드

이 문서는 GitHub 통합을 사용하여 Dev.to에 게시물을 발행할 때 참고할 수 있는 YAML Front Matter 가이드입니다.

## YAML Front Matter 형식

모든 Dev.to 게시물은 다음과 같은 YAML Front Matter로 시작해야 합니다:

```yaml
---
title: "게시물 제목"
published: false # 또는 true
description: "게시물 설명"
tags: tag1, tag2, tag3, tag4
cover_image: https://example.com/your-image.jpg
series: "시리즈 이름"
canonical_url: https://your-original-post-url.com
---
```

## 주요 속성 설명

| 속성            | 필수 여부 | 설명                                            |
| --------------- | --------- | ----------------------------------------------- |
| `title`         | 필수      | 게시물 제목                                     |
| `published`     | 선택      | 게시 여부 (true/false). false면 초안으로 저장됨 |
| `description`   | 권장      | 게시물 요약. SEO 및 소셜 미디어 공유에 중요     |
| `tags`          | 권장      | 콤마로 구분된 태그 목록. 최대 4개 태그만 표시됨 |
| `cover_image`   | 선택      | 게시물 커버 이미지 URL                          |
| `series`        | 선택      | 게시물이 속한 시리즈 이름                       |
| `canonical_url` | 선택      | 원본 게시물 URL (크로스 포스팅 시 사용)         |
| `date`          | 선택      | 게시 날짜 (YYYY-MM-DD 형식)                     |

## GitHub으로 게시하는 방법

1. 마크다운 파일을 작성하고 저장소의 `posts/` 디렉토리에 추가합니다
2. 파일에 올바른 YAML Front Matter가 포함되어 있는지 확인합니다
3. GitHub에 변경사항을 커밋하고 푸시합니다
4. Dev.to가 자동으로 변경사항을 감지하고 게시물을 업데이트합니다

## 모범 사례

- **명확한 제목 사용**: 검색 엔진과 독자에게 게시물 내용을 명확히 전달하는 제목을 사용하세요
- **태그 최적화**: 관련성 높은 태그를 사용하고 태그는 4개 이하로 유지하세요
- **고품질 커버 이미지**: 시선을 끄는 관련 이미지를 사용하세요
- **시리즈 활용**: 연관된 게시물은 같은 시리즈로 묶어 독자 경험을 향상시키세요
- **초안으로 시작**: 처음에는 `published: false`로 설정하고 검토 후 게시하세요
