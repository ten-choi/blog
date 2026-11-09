---
title: "[ Django ] Django logging 하기"
labels: ["Python","django"]
published: true
date: 2022-08-18T18:46:25+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 140
tistoryUrl: "https://yeolceo.tistory.com/140"
tistoryCategory: "Python/django"
tistoryTags: []
tistoryPostedAt: "2022-08-18 18:46:25"
language: ko
bloggerPostId: "2410731518583399742"
---
#### ? **환경** 

Mac M1  
Python 3.9.12  
VsCode

#### ? **개요**

Django에서 logs폴더를 만들어 기록을 남겨봅시다!

#### ? **목차**

-   로깅에 필요한 설정
-   postman으로 테스트하기

## **\- 로깅에 필요한 설정**

djangoProject를 준비합니다. settings.py 에 해당 내용을 추가합니다.  

```bash
# 로그 형식 추가
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,  # True일경우 이미 존재하는 로거들을 비활성화
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',  # DEBUG가 True일 때 레코드를 전달합니다 뭔소린지
        },
    },
    # 로그텍스트 형식정의
    'formatters': {
        'formatNormal': {'format': '%(levelname)s %(message)s [%(name)s:%(lineno)s]'},
        'formatTime': {'format': '[%(asctime)s] %(levelname)s %(message)s', 'datefmt': "%Y-%m-%d %H:%M:%S"},
    },
    'handlers': {
        # 파일 저장방식
        'file': {
            'level': 'INFO',  # 설정한 레벨이상의 로그만 동작합니다.
            'class': 'logging.handlers.RotatingFileHandler',  # 파일처리 핸들러로 파일저장
            'filename': os.path.join(BASE_DIR.parent, "logs/admin_log"+datetime.datetime.now().strftime('%Y-%m-%d')+".log"),
            'encoding': 'UTF-8',  # 인코딩 깨지지 말라고
            'maxBytes': 1024 * 1024 * 5,  # 5 MB  /
            'backupCount': 5,
            'formatter': 'formatTime',
        },
        # 콘솔(터미널)에 출력
        'console': {
            'level': 'DEBUG',  # 설정한 레벨이상의 로그만 동작합니다.
            'class': 'logging.StreamHandler',  # stream으로 로깅출력
            'formatter': 'formatTime',
        },
    },
    # 설정한 레벨이상의 로그만 동작합니다.  DEBUG < INFO < WARNING < ERROR < CRITICAL
    'loggers': {
        # 종류
        'django.server': {
            'handlers': ['file', 'console'],
            'propagate': False,
            'level': 'DEBUG',  # 설정한 레벨이상의 로그만 동작합니다.
        },
        # 'django.server': {
        #     'handlers': ['file', 'console'],
        #     'propagate': False,
        #     'level': 'CRITICAL',
        # },
        # 'django.request': {
        #     'handlers': ['file', 'console'],
        #     'propagate': False,
        #     'level': 'DEBUG',
        # },

    },
}
```

이해하는데 도움이 되는 링크 

점프 투 장고: [https://docs.python.org/ko/3/library/logging.handlers.html#logging.NullHandler](https://docs.python.org/ko/3/library/logging.handlers.html#logging.NullHandler)

django: [https://docs.djangoproject.com/en/4.0/topics/logging/#topic-logging-parts-filters](https://docs.djangoproject.com/en/4.0/topics/logging/#topic-logging-parts-filters)

```bash
import logging
logger = logging.getLogger('django.server')

    def testFunc(self, request, *args, **kwargs):
        try:
            print(__name__)
            url = 'http://localhost:8080/v2/quick/testt/'
            logger.info('test1')
            logger.debug('test2')
            logger.critical('test3')
            logger.error('test4')
            logger.warning('test5')
            print(request)
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)
```

## **\- PostMan으로 테스트하기**

로그 세팅할 때 디렉터리 설정을 보고 본인이 원하는 위치에 logs 폴더를 만들어줍니다.

그리고 실행하면 해당 로그가 나옵니다.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/140/img.webp)

**? 근거 있는 조언은 언제나 환영합니다. 성실한 코딩 하세요.**
