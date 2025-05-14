---
title: "GitHub으로 Dev.to에 게시하는 방법"
published: true
description: "GitHub 통합 기능을 사용하여 마크다운 파일을 Dev.to에 게시하는 단계별 가이드"
tags: devto, github, blogging, tutorial
cover_image: https://images.unsplash.com/photo-1618401471353-b98afee0b2eb
series: "Dev.to 게시 가이드"
---

# GitHub으로 Dev.to에 게시하는 방법

이 가이드에서는 GitHub 저장소를 사용하여 Dev.to에 블로그 게시물을 발행하는 방법을 설명합니다. API 키가 필요 없는 간단한 방법입니다!

## 필요한 것

- GitHub 계정
- Dev.to 계정
- 마크다운으로 작성된 게시물

## 1단계: 블로그 저장소 설정하기

먼저 GitHub에 블로그 게시물을 저장할 저장소를 만듭니다. 기존 저장소를 사용하거나 새 저장소를 만들 수 있습니다.

```bash
# 로컬에 저장소 복제하기
git clone https://github.com/yourusername/your-blog-repo.git
cd your-blog-repo
```

## 2단계: 마크다운 파일 구조 만들기

각 블로그 게시물은 다음과 같은 YAML Front Matter가 포함된 마크다운 파일입니다:

```markdown
---
title: "게시물 제목"
published: false # true로 설정하면 즉시 공개됩니다
description: "게시물 설명"
tags: tag1, tag2, tag3
cover_image: https://example.com/your-cover-image.jpg
series: "시리즈 이름"
---

여기에 게시물 내용을 작성합니다...
```

## 3단계: Dev.to와 GitHub 통합하기

1. Dev.to 계정에 로그인합니다
2. 프로필 설정으로 이동합니다 (우측 상단의 프로필 사진 클릭 > Settings)
3. "Extensions" 탭을 클릭합니다
4. "GitHub" 섹션에서 "Connect GitHub Account" 버튼을 클릭합니다
5. GitHub 계정에 로그인하고 권한을 부여합니다
6. Dev.to에서 게시물을 가져올 저장소를 선택합니다
7. 게시물 경로 패턴을 설정합니다 (예: `/posts/*.md`)

## 4단계: 게시물 발행하기

게시물을 발행하려면:

1. 마크다운 파일을 저장소에 추가하고 커밋합니다
2. GitHub에 푸시합니다
3. Dev.to가 자동으로 저장소를 확인하고 새 게시물이나 업데이트된 게시물을 가져옵니다

```bash
git add posts/새-게시물.md
git commit -m "새 게시물 추가: 제목"
git push origin main
```

## 게시물 업데이트하기

게시물을 업데이트하려면 마크다운 파일을 수정하고, 커밋하고, 푸시하면 됩니다. Dev.to는 자동으로 변경 사항을 감지하고 게시물을 업데이트합니다.

## 팁

- `published: true`로 설정하면 게시물이 즉시 공개됩니다
- `published: false`로 설정하면 게시물이 초안으로 저장됩니다
- 커스텀 도메인에서 원본 게시물이 있는 경우 `canonical_url`을 사용하세요
- 시리즈 게시물을 만들려면 모든 게시물에 동일한 `series` 값을 사용하세요

## 결론

GitHub 통합을 사용하면 API 키 없이도 쉽게 Dev.to에 게시물을 발행하고 관리할 수 있습니다. 마크다운으로 콘텐츠를 작성하고, Git 워크플로우를 사용하여 게시물을 관리하세요.

질문이나 의견이 있으면 댓글로 알려주세요!
