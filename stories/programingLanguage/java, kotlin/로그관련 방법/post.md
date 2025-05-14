로그를 만들어 봅시다

아래와 같이 로그를 만드는 설정을 해줍니다

```yml
Configuration:
  name: Default
  status: warn
  Properties:
    Property:
      name: log-path
      value: "logs"
  Appenders:
    Console:
      name: Console_Appender
      target: SYSTEM_OUT
      PatternLayout:
        pattern: "[%-5level] %d{yyyy-MM-dd HH:mm:ss.SSS} [%t][%F %M] %c{1} - %msg%n"
    RollingFile:
      - name: RollingFile_Appender
        fileName: ${log-path}/rollingfile.log
        filePattern: "${log-path}/archive/rollingfile.log_%d{yyyy-MM-dd}.gz"
        PatternLayout:
          pattern: "[%-5level] %d{yyyy-MM-dd HH:mm:ss.SSS} [%t][%F %M] %c{1} - %msg%n"
        Policies:
          TimeBasedTriggeringPolicy:
            Interval: 1
            modulate: true
        DefaultRollOverStrategy:
          Delete:
            basePath: "${log-path}/archive"
            maxDepth: "1"
            IfAccumulatedFileCount:
              exceeds: 7
  Loggers:
    Root:
      level: debug # 기본 로그 수준
      AppenderRef:
        - ref: Console_Appender
        - ref: RollingFile_Appender
#Profiles:
#  dev:
#    Loggers:
#      Root:
#        level: debug  # 개발 환경은 debug 이상
#
#  prod:
#    Loggers:
#      Root:
#        level: warn  # 프로덕션 환경은 warn 이상
#spring:
#  profiles:
#    active: dev  # 또는 prod로 설정 가능
```

로그를 가장앞부분과 마지막 부분에 설정하는 설정을 해봅시다

aop의 일부라고도 볼수있습니다

이렇게해야 모든 controller에 log 를 사용하는것을 방지할수있습니다

시작과 끝에 로그를 박습니다

그렇게 설정하면 모든 시작과 끝의 로그를 알수있습니다

나머지는 직접 throw하는 부분의 로그만 설정하면됩니다

이부분은 에러가 발생했을때 log를 남기는 부분을 설정하기때문에

response쪽과 관계를 고려 하여 설정하면 문제가 없습니다
