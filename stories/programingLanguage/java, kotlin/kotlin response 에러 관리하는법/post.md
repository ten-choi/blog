# Error handleing pracice in kotlin

# Error Handling Best Practices in Kotlin

## 1. Common Error Code for Throwing Errors

In Kotlin, error handling is an essential part of writing clean and maintainable code. Here’s a basic approach to manage errors effectively:

- **Define common error codes**: Create reusable error codes to maintain consistency when throwing exceptions.
- **Create custom error handling annotations**: Implement custom annotations that can be used for error handling.
- **Throw errors in a common error handling module**: Centralize your error handling logic in a common module that can be reused across different parts of your application.

## 2. Handling Edge Cases

There are certain scenarios where the error handling mechanism might not work as expected. For instance:

- **Token filtering before entering the internal system**: If token filtering occurs before the error handler is initialized, the handler might not function properly.
- **Handling unexpected errors**: How to handle errors that occur unexpectedly but are not part of the normal error flow.

## Kotlin Annotation Validation

### How to Validate Annotations in Kotlin

I’ve been trying to implement annotation validation in Kotlin, but it didn’t work as expected. Despite many attempts and methods, I’ve reached a conclusion.

- **Add `@Validated` at the class level**: This is necessary to trigger validation in controllers that use annotation-based validation.
  ```kotlin
  import org.springframework.validation.annotation.Validated
  ```

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
