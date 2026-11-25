---
title: "[ Django ] Logging in Django"
labels: ["Python","django","Archive"]
published: true
date: 2022-08-18T18:46:25+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 140
tistoryUrl: "https://yeolceo.tistory.com/140"
tistoryCategory: "Python/django"
tistoryTags: []
tistoryPostedAt: "2022-08-18 18:46:25"
language: en
bloggerPostId: "2410731518583399742"
---
#### ? **Environment**

Mac M1  
Python 3.9.12  
VsCode

#### ? **Overview**

Let's create a logs folder in Django and write logs to it!

#### ? **Contents**

-   Settings needed for logging
-   Testing with Postman

## **\- Settings Needed for Logging**

Prepare a Django project and add the following to settings.py.  

```bash
# add the log configuration
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,  # if True, disables loggers that already exist
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse',
        },
        'require_debug_true': {
            '()': 'django.utils.log.RequireDebugTrue',  # passes records on only when DEBUG is True (no idea what that means)
        },
    },
    # define the log text formats
    'formatters': {
        'formatNormal': {'format': '%(levelname)s %(message)s [%(name)s:%(lineno)s]'},
        'formatTime': {'format': '[%(asctime)s] %(levelname)s %(message)s', 'datefmt': "%Y-%m-%d %H:%M:%S"},
    },
    'handlers': {
        # save to a file
        'file': {
            'level': 'INFO',  # only logs at or above this level are handled
            'class': 'logging.handlers.RotatingFileHandler',  # save to a file using a file handler
            'filename': os.path.join(BASE_DIR.parent, "logs/admin_log"+datetime.datetime.now().strftime('%Y-%m-%d')+".log"),
            'encoding': 'UTF-8',  # so the encoding doesn't break
            'maxBytes': 1024 * 1024 * 5,  # 5 MB  /
            'backupCount': 5,
            'formatter': 'formatTime',
        },
        # print to the console (terminal)
        'console': {
            'level': 'DEBUG',  # only logs at or above this level are handled
            'class': 'logging.StreamHandler',  # log output via a stream
            'formatter': 'formatTime',
        },
    },
    # only logs at or above the set level are handled.  DEBUG < INFO < WARNING < ERROR < CRITICAL
    'loggers': {
        # logger types
        'django.server': {
            'handlers': ['file', 'console'],
            'propagate': False,
            'level': 'DEBUG',  # only logs at or above this level are handled
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

Helpful links for understanding this

Jump to Django: [https://docs.python.org/ko/3/library/logging.handlers.html#logging.NullHandler](https://docs.python.org/ko/3/library/logging.handlers.html#logging.NullHandler)

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

## **\- Testing with Postman**

Check the directory in the log settings and create a logs folder wherever you want.

Then run it, and the logs show up.

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/140/img.webp)

**? Well-grounded advice is always welcome. Happy coding, and keep at it.**
