# Error handleing pracice in kotlin

kotlin에서 에러 핸들러를 만들일이 생겼다

가독성 좋은 에러 관리법

kotlin에서 에러 컨트롤 하는법

throw를 할 공통 에러 코드를 만든다
에러 처리용 annotation을 만든다

공통 에러 처리 모듈에 throw를 한다

위에 해당되지않는 부분

1. token fillter 할때 아직 내부가 아니라서 에러 핸들러 작동이 안될경우
2. 의도하지 않은 에러가 나타났을때 의 처리

Kotlin annotation validation 하는법
하는법
kotlin으로 annotation validation을 하려고한다 
ㅈㄴ 안된다 이런저런 방법을 찾아보고 있다
많은걸 시도해도 안됬다 결과는 정해졌다

class최상단에 
import org.springframework.validation.annotation.Validated
컨트롤러단에서 어노테이션 벨리데이션 할경우 이거 무조건넣어야한다
requestBody에서 하려면 그 앞단에 붙여줘야하는듯 하다 
@RequestBody @Validated requestBody: CreateOrganizationRequestBodyDto

위와 비교하면 class의 선언부 같은 느낌인데 requestBody쪽은 왜 저기 선언하는 지는 알수없다
역할: 클래스 수준의 @Validated는 주로 @Valid 또는 @Validated 어노테이션이 붙은 메서드 파라미터의 유효성 검사를 지원하기 위해 사용됩니다. 또한, 클래스 내에서 AOP(Aspect-Oriented Programming) 기능과 함께 사용되어 특정 유효성 검사 그룹을 활성화할 때도 사용됩니다.
한계: 클래스 최상단에 선언된 @Validated는 클래스 내의 모든 메서드에 대한 전역적인 유효성 검사 기능을 활성화하지만, 각 메서드 파라미터의 유효성 검사에는 영향을 주지 않습니다. 이는 메서드 파라미터에 대한 유효성 검사를 자동으로 활성화하지 않기 때문에, 메서드 파라미터에 별도로 @Validated 또는 @Valid를 붙여야 합니다.

아래의 의존성을 추가하지않으면 안된다 
내경우에는
// have to annotation validation
implementation("org.springframework.boot:spring-boot-starter-validation:3.3.2")

import jakarta.validation.constraints.NotNull
import jakarta.validation.Valid
위의 코드들이 기본적으로 추가가 가능했기때문에 해당의존성을 추가할 필요가 없다고 판단하고 이런 저런 시도를 했지만 불가능했다
결론적으로는 위의 validation의 존성은 필수였다 이유를 찾아보았다
위의 의존성을 추가하지않으면 존재하는 하지만 구현하지않는다고 나와있다
hivernate validator가 작동해야하는데 없다고한다

아래와같은 비슷하게 생긴의존성이 젯브레인에서 제공하지만
유효성검사를 하지않는 껍데기이다. 직접 validation코드를 작성하지않는이상 유효성검사를 자동으로 하진않는다

kotlin에서는 타입을 적어 작성하기때문에 어노테이션으로 널이면 안된다는걸 적을 이유가 없는데 왜존재한는지 모르겠다.
그저 내가 헷갈려서 그럴수도있지만 내경우엔 불필요한 코드였다
내가 모르는 부분이 있고 저게 의미있는 의존성이라면 코멘트 바란다
import org.jetbrains.annotations.NotNull

나는 dto로도 하고싶지만 직접도 설정하고싶었다

아래와 같은 방식으로 설정이 가능했다
이경우 custom annotation의 설정은 field가아닌 VALUE_PARAMETER로 사용하면 문제가 없었다
@RequestAttribute("userId") @ValidEmail(message = "") userId: String,

정상적으로 동작하는것을 확인했다 휴
3개중 하나라도 없으면 annotation class에서 에러가 나오니까 하나도 뺄수없다

```kotlin
@Target(AnnotationTarget.VALUE_PARAMETER)
@Retention(AnnotationRetention.RUNTIME)
@Constraint(validatedBy = [IsObjectIdHandler::class])
annotation class ObjectIdOnly(
val message: String = "is not objectId from mongo",
val groups: Array<KClass<\*>> = [],
val payload: Array<KClass<out Payload>> = []
)
```

그리고 아래처럼 코드를 만들면 payload가 맞는지 아닌지 boolean을 리턴하는 형식이다나는 아래에서 커스텀 exceptionhanler를 적용에서 글로벌에서 캐치하고싶었지만 그것은 불가능했다

```kotlin
class IsObjectIdHandler : ConstraintValidator<ObjectIdOnly, String> {
override fun isValid(payload: String, p1: ConstraintValidatorContext?): Boolean {
return ObjectId.isValid(payload)
}
}
```

annotation을 핸들링할때 에러를 일으키면 false일경우 정해져있는 에러인 
ConstraintViolationException class의 에러를 발생시키지만 
throw CoustomException을 해버릴경우 거기서의 exception처리 자체가 에러라고 인식해서 일반에러를 작동시키기때문에 컨트롤할수없다
그래서message에는 간단한 설명을 적지만 나는 errorCode를 정리해서 사용하고싶었다
그래서 ConstraintViolationException를 globalExceptionHandler에 적용시켰고 description에서 controller에서 원하는 값이 오지않은경우의
errorCode를 작성후 description을 var로 변경하여 
필요시에 설명의 접미 부분에 key, value 값을 추가할수있게끔 하였다
아래과 같이 코드가 나왔으며 핸들링이 가능해졌고 원하는 코드만 리턴할수있는 글로벌 핸들러를 만들었다

```kotlin
@ExceptionHandler(ConstraintViolationException::class)
fun test(
request: HttpServletRequest,
ex: ConstraintViolationException,
): ResponseEntity<ApiFailureResponseDto<ApiFailureResponseDto.ErrorDetail>> {
logError(request, ex)
val test = ErrorCodes.VALIDATION_ERROR
val test2 = ex.constraintViolations.joinToString(", ") {
"${it.propertyPath}: ${it.invalidValue}"
}
test.description = test2 + test.description
return buildErrorResponse(
ex,
ErrorCodes.VALIDATION_ERROR
)
}
```

기본의 ExceptionHandler를 최하단에 두지않으면 기존 핸들러가 먼저 동작할수있는부분을 유의하자
위와같이 하면 annotation Exception Handler설정이 문제없이 동작한다
파라미터의 모든 이슈는 contoller에서 해결하면서 annotation을 활용해 깔끔하게 처리하고싶었던 부분이 컷기때문에 위와같은 코드를 만들게 되었다
validation 의존성 추가안해도 껍질만있는건 내가 제대로 안읽은 부분도 있지만 기동하지못하는 코드가 껍질만 선언이 가능한거 자체가 마음에 들지않았다

다른 참조글에서도 무조건 추가한다 
https://www.geeksforgeeks.org/spring-boot-validation-using-hibernate-validator/
https://www.baeldung.com/kotlin/valid-spring-annotation
https://hibernate.org/validator/
