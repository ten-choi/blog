# Swagger(OpenAPI)를 사용하는 이유

Swagger(현재 OpenAPI)는 API 개발과 문서화에서 중요한 역할을 합니다. Swagger를 사용하면 API를 관리하고 테스트할 수 있는 UI를 제공하며, API 명세서를 자동으로 작성하고 다른 개발자들이 API를 쉽게 이해하고 사용할 수 있도록 도와줍니다. Swagger를 사용하는 이유는 다음과 같습니다.

## 1. API 문서화를 자동화

API를 개발하면서 별도로 문서를 작성하는 것은 시간이 많이 걸리고, 실수나 누락이 발생할 가능성이 높습니다. Swagger는 개발자가 작성한 API 명세를 기반으로 자동으로 API 문서를 생성합니다. 이를 통해 API의 엔드포인트, 요청/응답 형식, 데이터 모델 등을 일관되게 관리할 수 있습니다.

## 2. API 테스트 가능

Swagger는 API를 문서화하는 것뿐만 아니라, **실제 API 호출을 테스트**할 수 있는 기능도 제공합니다. Swagger UI를 통해 사용자는 간단히 버튼 클릭으로 API를 호출하고 응답을 확인할 수 있습니다. 이는 Postman과 유사하지만, Swagger UI는 웹 브라우저에서 직접 실행되므로, API를 더 직관적으로 테스트하고 디버깅할 수 있습니다.

## 3. 협업 향상

API 명세서를 Swagger로 작성하면 개발자, 프론트엔드 개발자, QA팀, 심지어 비즈니스 팀 등 다양한 이해관계자와 **효율적인 소통**이 가능해집니다. 명확한 API 명세서와 UI를 통해 팀 간의 오해를 줄이고, 개발 진행 상황을 공유할 수 있습니다. Swagger는 API의 동작을 직관적으로 보여주기 때문에 다른 팀들이 개발 중인 API를 쉽게 이해하고 사용할 수 있습니다.

## 4. 클라이언트와 서버의 동기화

Swagger 명세서에 정의된 API가 정확하게 구현되도록 유도하며, **클라이언트와 서버 간의 동기화**를 맞추는 데 유용합니다. 클라이언트 개발자는 Swagger UI를 통해 API의 요청 및 응답 형식을 확인하고, 서버 개발자는 이를 바탕으로 API를 구현할 수 있습니다.

## 5. 기술적 부하 감소

Swagger를 사용하면 API 문서를 수동으로 작성하는 대신, API의 구현을 기반으로 자동으로 문서가 생성됩니다. 이로 인해 **문서 작성에 소요되는 시간**이 크게 줄어들며, 개발자는 코드 작성에 더 많은 시간을 투자할 수 있습니다.

## 6. 두 가지 라이브러리: SpringFox vs Spring-Doc

Swagger는 두 가지 주요 라이브러리, **SpringFox**와 **Spring-Doc**을 통해 통합할 수 있습니다.

- **SpringFox**: 오래된 라이브러리이며, 2020년 이후 업데이트가 없습니다.
- **Spring-Doc**: 2019년에 나온 라이브러리로, 꾸준히 업데이트되고 있어 최신 Spring Boot 버전과의 호환성이 높습니다. 이 글에서는 최신 라이브러리인 **Spring-Doc**을 활용하는 방법을 소개합니다.

## 7. 간편한 설정과 사용

Swagger를 프로젝트에 통합하는 것은 **간단한 설정**만으로 가능하며, Spring Boot와 같은 프레임워크에서는 몇 가지 의존성을 추가하고, 설정 클래스를 통해 자동으로 Swagger UI를 제공할 수 있습니다. 이를 통해 추가적인 복잡한 설정 없이 빠르게 API 문서화와 테스트가 가능합니다.

## 사용된 Swagger 태그 설명

Swagger에서 사용된 주요 태그들을 아래와 같이 정리할 수 있습니다.

### 1. `@Tag`

`@Tag`는 API 엔드포인트를 그룹화하거나 설명을 추가하는 데 사용됩니다.

- **`name`**: 태그 이름
- **`description`**: 태그 설명

#### 예시:

```kotlin
@Tag(name = ReleaseOpenApi.TAG_NAME, description = ReleaseOpenApi.TAG_DESCRIPTION)


@Operation(
    summary = ReleaseOpenApi.GETS_SUMMARY,
    description = ReleaseOpenApi.GETS_DESCRIPTION
)


@Schema(description = ENG_AND_NUM_ONLY + NO_WHITE_SPACE, minLength = appNameMin, maxLength = appNameMax)


Swagger(OpenAPI)는 API 개발의 효율성을 크게 향상시키는 도구입니다. 자동화된 문서화, 실시간 API 테스트, 협업 향상 등의 이점을 제공하며, 이를 통해 개발자들은 더 빠르고 정확하게 API를 개발하고 관리할 수 있습니다. Swagger 태그를 활용하면 API를 더 직관적으로 문서화하고, 팀 간의 협업을 원활하게 할 수 있습니다.

위 Markdown 파일은 Swagger를 사용해야 하는 이유와 함께 Swagger에서 사용되는 주요 태그들에 대한 설명을 제공합니다. 각 태그에 대한 간단한 예시 코드와 설명도 포함되어 있어 실제 코드와 함께 이해할 수 있도록 구성되었습니다.
```
