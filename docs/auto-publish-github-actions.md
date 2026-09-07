# Blogger 자동 배포 (GitHub Actions) 설계 메모

> 상태: **설계 단계** (아직 구현 안 함). 이 문서는 "어떻게 할지" 정리용.
> 작성일: 2026-09-07

## 1. 목표

- 대상: `content/dev/database/` 아래 `published: false` 인 md 파일
- 목적지: dev 블로그 (ten-dev-notes.blogspot.com, Blog ID `3666962477256387094`)
- 빈도: **하루 2회**, 1회 1개 글
  - 오전 슬롯: **08:00 ~ 13:00 KST** 사이 랜덤 1회
  - 오후 슬롯: **15:00 ~ 18:00 KST** 사이 랜덤 1회
- 실행 주체: **GitHub Actions** (로컬 PC 꺼져 있어도 돌아야 함)
- 배포 후 md 파일의 `published: true` / `bloggerPostId` 변경을 **main에 커밋 + push** (다음 실행이 같은 글을 다시 올리지 않도록)

## 2. 현재 상태 (조사 결과)

| 항목 | 상태 |
|---|---|
| 저장소 | `ten-choi/blog`, **public**, 기본 브랜치 `main` |
| 배포 코드 | `platforms/blogger/publish.ts` (insert/update 자동 판별, `bloggerPostId` 를 frontmatter에 write-back) |
| 인증 코드 | `platforms/blogger/auth.ts` (refresh token 있으면 무인 동작, 없으면 브라우저 OAuth 대기 → CI에서는 hang) |
| 기존 자동화 | `tools/auto-publish-next.ps1` + `tools/register-auto-publish-task.ps1` (Windows 작업 스케줄러 방식). **현재 태스크 미등록 상태** → 중복 배포 위험 없음 |
| GitHub Actions | `.github/workflows/` 없음 (신규) |
| 대기 글 | database 22개 중 **13개** (`4.1` ~ `7.2`). 파일명 숫자 prefix 덕분에 알파벳 정렬 = 시리즈 순서 |
| 소진 예상 | 13개 ÷ 2개/일 ≈ **7일** |

기존 ps1 로직(알파벳 첫 `published: false` 선택 → true로 flip → publish → 커밋)은 그대로 살려서 CI용으로 포팅하면 된다.

## 3. 시크릿 (토큰) — 어디에 넣나

**GitHub 저장소 → Settings → Secrets and variables → Actions → Repository secrets** 에 등록.
yaml `env:` 에 값을 직접 쓰면 public 저장소라 그대로 노출되므로 **절대 금지**. yaml에서는 `${{ secrets.이름 }}` 으로만 참조.

로컬 `.env` 의 아래 4개 값을 그대로 옮긴다 (이름도 동일하게 두면 코드 수정 불필요):

| Secret 이름 | 내용 | 출처 |
|---|---|---|
| `BLOGGER_CLIENT_ID` | OAuth client_id (`...apps.googleusercontent.com`) | `.env` |
| `BLOGGER_TOKEN_PROD` | OAuth client_secret (`GOCSPX-...`) — 이름이 TOKEN이지만 실제로는 client secret | `.env` |
| `BLOGGER_REFRESH_TOKEN` | refresh token | `.env` |
| `BLOGGER_BLOG_ID` | `3666962477256387094` (dev) | `.env` 의 `BLOGGER_BLOG_ID_DEV` 값 |

- `BLOGGER_BLOG_ID` 는 비밀은 아니지만 편의상 secret 또는 `vars` 에 두면 됨. `publish.ts` 가 `process.env.BLOGGER_BLOG_ID` 를 읽으므로 이 이름으로 넣는다.
- `.env` 파일 자체는 `.gitignore` 에 있으므로 커밋되지 않는다 (확인 완료).

### ⚠️ 반드시 확인: OAuth 앱의 "게시 상태"
Google Cloud Console → API 및 서비스 → OAuth 동의 화면 → **게시 상태가 "테스트(Testing)"이면 refresh token이 7일 후 만료**된다.
그러면 자동 배포가 일주일 뒤에 조용히 깨진다. **"프로덕션(In production)"** 으로 바꿔 둘 것 (본인 계정만 쓰는 용도라 검증 심사 없이도 동작함, 경고 화면만 뜸).

## 4. "랜덤 시간" 을 GitHub Actions 에서 만드는 법

GitHub cron 은 고정 시각만 지원하고, 실행이 수 분~수십 분 늦는 경우도 잦다. 두 가지 방법이 있다.

### 방법 A (추천): 30분 간격 tick + 하루 단위 결정적 랜덤 목표시각
- 슬롯 창 안에서 **30분마다 워크플로를 깨운다** (tick).
- 각 tick 은 `sha256("YYYY-MM-DD-am")` 같은 시드로 **그날의 목표 시각**을 계산 (모든 tick 이 같은 값을 얻음).
  - am: `08:00 + (seed % 271)분` → 08:00 ~ 12:30
  - pm: `15:00 + (seed % 151)분` → 15:00 ~ 17:30
- 조건 `현재시각 >= 목표시각` **그리고** `이 슬롯에 아직 배포 안 함` 이면 배포, 아니면 즉시 종료(~20초).
- "이미 배포했는지"는 커밋 메시지 마커로 판단: 슬롯 시작 이후 `git log --grep "\[auto-publish am\]"` 이 있으면 skip.
- 장점: cron 이 늦거나 한 번 빠져도 다음 tick 이 받아줌. 러너 점유 짧음.
- 단점: 스크립트에 목표시각/마커 판정 로직이 들어감 (bash 30줄 정도).

### 방법 B (단순): 슬롯 시작에 1회 기동 → `sleep` 랜덤
- 08:00 KST 에 기동 → `sleep $((RANDOM % 16200))` (0~4.5h) → 배포.
- 장점: yaml 20줄로 끝.
- 단점: 러너를 최대 5시간 점유 (public 이라 비용 0 이지만), cron 자체가 skip 되면 그 슬롯은 유실. 6시간 job 제한은 문제 없음.

**결정: 방법 A 로 간다** (신뢰성). B 는 A 가 번거로우면 대체안.

### cron 표 (GitHub cron 은 UTC, KST = UTC+9)

| KST | UTC | cron (방법 A, 30분 tick) |
|---|---|---|
| 08:00 ~ 12:30 (am) | 23:00 전날 ~ 03:30 | `*/30 23 * * *`, `*/30 0-3 * * *` |
| 13:00 (am 마감 catch-up) | 04:00 | `0 4 * * *` |
| 15:00 ~ 17:30 (pm) | 06:00 ~ 08:30 | `*/30 6-8 * * *` |
| 18:00 (pm 마감 catch-up) | 09:00 | `0 9 * * *` |

- 슬롯 판정: UTC 시각이 23:00~04:00 이면 `am`, 06:00~09:00 이면 `pm`.
- "그날" 날짜는 **KST 기준**으로 계산 (`TZ=Asia/Seoul date +%F`) — 안 그러면 am 슬롯이 UTC 전날/당일로 갈라진다.
- 정각(`:00`)은 GitHub 부하로 지연이 심하므로 실제로는 `7,37` 같은 오프셋 분을 쓰는 게 낫다.

## 5. 워크플로 설계 `.github/workflows/auto-publish.yml`

```
on:
  schedule: (위 cron 들)
  workflow_dispatch:      # 수동 테스트용. input: force=true 면 시각/마커 무시하고 1개 배포
permissions:
  contents: write         # write-back 커밋 push 용
concurrency:
  group: auto-publish     # tick 겹침 방지
  cancel-in-progress: false
timeout-minutes: 10       # auth.ts 가 브라우저 대기로 hang 하면 여기서 죽임
```

Job 단계:
1. `actions/checkout` (`fetch-depth: 0` — 마커 커밋 grep 에 히스토리 필요)
2. **decide** (bash): 슬롯 판정 → 목표시각 계산 → 마커 확인 → `run=true|false` output
3. `if: run == 'true'` 이하 진행
4. `actions/setup-node` (Node 22) + `npm ci`
5. **fail-fast**: `BLOGGER_REFRESH_TOKEN` 비어 있으면 즉시 exit 1 (auth.ts 의 대화형 fallback 진입 방지)
6. `npx ts-node tools/auto-publish-next.ts --dir content/dev/database` (아래 6절)
   - env: 4개 secrets
7. `git config user.name "github-actions[bot]"` / email `41898282+github-actions[bot]@users.noreply.github.com`
8. `git add <그 파일>` → `git commit -m "publish(dev): <title> [auto-publish am]"` → `git pull --rebase origin main` → `git push`
9. 실패 시 GitHub 기본 이메일 알림 (workflow failure) 로 충분. Notion/msg.exe 알림은 CI 에선 제거.

## 6. 선택 스크립트 `tools/auto-publish-next.ts` (ps1 포팅)

기존 `tools/auto-publish-next.ps1` 의 로직을 Node/TS 로 옮긴다 (ubuntu 러너에서 실행하기 위해).

- 입력: `--dir <경로>` (기본 `content/dev/database`), `--dry-run`
- 순서:
  1. `--dir` 아래 `*.md` 를 파일명 정렬 → frontmatter `published: false` 인 첫 파일 선택. 없으면 `"Queue empty"` 출력 후 **exit 0** (실패 아님)
  2. `published: false` → `published: true` 치환 (UTF-8 no BOM 유지)
  3. `publish.ts` 의 publish 함수 호출 (또는 `npm run publish:blogger -- <file>` spawn). 성공하면 `publish.ts` 가 `bloggerPostId` 를 write-back
  4. 실패 시 원본 내용으로 되돌리고 exit 1 (Blogger insert 가 성공한 뒤 실패했으면 되돌리지 않음 — ps1 과 동일한 규칙)
  5. 선택된 파일 경로와 title 을 `$GITHUB_OUTPUT` 에 기록 (커밋 메시지용)
- ps1 과 달리 `content/dev` 전체가 아니라 **`--dir` 로 범위 제한** (이번 요구: database 만)

## 7. 주의사항 / 리스크

- **로컬 작업 전 `git pull` 필수.** Actions 가 main 에 커밋을 쌓으므로 로컬에서 그냥 push 하면 reject 된다.
- **`auth.ts` 의 refresh token 갱신 write-back**: 토큰이 회전되면 `.env` 에 쓰려고 하는데 CI 에는 `.env` 가 없다 → 파일 생성만 되고 버려짐. Google 은 보통 refresh token 을 회전시키지 않으니 실제 문제는 거의 없지만, 3절의 "프로덕션 상태" 를 안 맞추면 7일 만료로 확실히 깨진다.
- **GitHub 의 cron 자동 비활성화**: 60일간 저장소 활동이 없으면 schedule 이 꺼진다. 자동 커밋이 활동으로 잡히므로 큐가 살아있는 동안은 문제 없음. 큐 소진 후 오래 방치하면 다음에 글 추가할 때 Actions 탭에서 다시 켜야 할 수 있음.
- **중복 배포 방지 2중**: (1) 마커 커밋 grep, (2) `concurrency` 그룹. 둘 다 있어야 tick 이 겹칠 때 안전.
- **큐 소진**: 13개 끝나면 매 tick 이 "Queue empty" 로 정상 종료. 이후 다른 카테고리로 확장하려면 `--dir` 인자만 바꾸거나 여러 dir 을 순서대로 넘기면 됨.
- **기존 ps1 스크립트**: Windows 태스크는 이미 미등록. `tools/*.ps1` 과 `tools/*.log` 는 Actions 전환 후 삭제하거나 "수동 실행용" 으로 남길지 결정.
- **`_archive/`** 는 스캔 범위 밖이라 영향 없음.

## 8. 작업 체크리스트

- [ ] Google Cloud Console 에서 OAuth 동의 화면 게시 상태 확인 → 프로덕션으로 변경
- [ ] GitHub Secrets 4개 등록 (`BLOGGER_CLIENT_ID`, `BLOGGER_TOKEN_PROD`, `BLOGGER_REFRESH_TOKEN`, `BLOGGER_BLOG_ID`)
- [ ] `tools/auto-publish-next.ts` 작성 (ps1 포팅, `--dir`, `--dry-run`)
- [ ] `.github/workflows/auto-publish.yml` 작성 (방법 A)
- [ ] `workflow_dispatch` + `force=true` 로 수동 1회 테스트 → Blogger 에 글 올라가고 main 에 커밋 push 되는지 확인
- [ ] 로컬 `git pull` 해서 write-back 커밋 받기
- [ ] 첫 자동 슬롯(다음날 오전) 결과 Actions 로그 확인
- [ ] 기존 `tools/*.ps1` 처리 결정 (삭제 or 유지)

## 9. 미결정 사항 (사용자 결정 필요)

1. **주말 포함?** 현재 설계는 매일(월~일). 기존 ps1 은 월~금만이었음. 평일만이면 cron 에 `1-5` 요일 조건 추가 — 단 UTC 23:00 tick 은 전날이라 요일이 하나 밀리는 점 주의.
2. **방법 A vs B** — 추천은 A. 단순함이 더 중요하면 B.
3. **큐 소진 후** 다른 카테고리(algorithms, system design 등)로 자동 확장할지, database 만 하고 멈출지.
4. **기존 ps1/log 파일** 삭제 여부.
