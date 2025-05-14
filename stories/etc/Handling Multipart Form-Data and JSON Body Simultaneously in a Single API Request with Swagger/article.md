Handling Multipart Form-Data and JSON Body Simultaneously in a Single API Request with Swagger

To handle multipart/form-data and a JSON body simultaneously in a single API request using Swagger, follow these steps

![Preview Image](${https://helpx.adobe.com/content/dam/help/en/photoshop/using/quick-actions/remove-background-before-qa1.png})

# Multipart/form-data와 JSON 바디를 동시에 처리하기

## Define the problem

I’m trying to upload a file using the multipart/form-data content type and also include a request body in the same request.

However, since application/json cannot coexist with multipart/form-data,
I considered receiving the body as a string and then converting it to JSON. But this approach changes the DTO in Swagger to a string, which is not good for me.

So, I’m trying to solve this problem.

## Server Spec

- **Kotlin**: 1.9.x
- **Spring Boot**: 3.2.x

## Examine

There is no problem when used in the following way.

```kotlin
import com.test.dto.BodyDto

@Operation(summary = "Upload File", description = "")
@PostMapping("", consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
fun uploadFile(
    @RequestPart("file") file: MultipartFile,
    @PathVariable pathValue: String,
    @RequestPart(value = "body") requestJson: String,
): ResponseEntity<Nothing> {
    // 파일 업로드 및 JSON 처리
}
```

I wanted to implement it as shown in the code below, but it results in an error.

```kotlin
import com.test.dto.BodyDto

@Operation(summary = "upload file", description = "")
@PostMapping("", consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
fun uploadFile(
    @RequestPart("file") file: MultipartFile,
    @PathVariable pathValue: String,
    @RequestBody(value = "body") requestBody:BodyDto
): ResponseEntity<Nothing> {

}
```

This error occurs Content type ‘application/octet-stream’ not supported

I examined two methods to resolve the above error

1. extend AbstractJackson2HttpMessageConverter
2. swagger add schema

## Diagnose

In my case, the first method didn’t work the problem.

The second method was effective and simple, so I chose this method

```kotlin
import com.test.dto.BodyDto
@Operation(summary = "upload file", description = "")
@PostMapping("", consumes = [MediaType.MULTIPART_FORM_DATA_VALUE])
fun uploadFile(
    @RequestPart("file") file: MultipartFile,
    @PathVariable pathValue: String,
    @Parameter(
        required = true,
        schema = Schema(implementation = BodyDto::class)
    )
    @RequestPart(value = "body") requestBodyAsJson: String,
): ResponseEntity<Nothing> {
val requestBody = Gson().fromJson(requestBodyAsJson,
                              BodyDto::class.java)
}
```

In the swagger, set the type separately and enter it as string.
It is a method of converting to JSON format through DTO.
I can see the swagger in the object format I want as shown below.

![Description](https://img.notionusercontent.com/s3/prod-files-secure%2F6ab3efe6-44b5-4e5c-9d86-56543fb7f59d%2Fc3b86c80-eaba-4a31-971d-868a2b179849%2Ftest2.jpg/size/w=1420?exp=1727749267&sig=VX63E66yaxZvLTyfE2Db1fyK5g_lgajo6O10Oikoyq0)

## Cure

I solved the problem because the swagger’s document comes out as DTO while requesting file and body at the same time.

Your comments are always welcome. Thank you for reading

ref

https://stackoverflow.com/questions/16230291/requestpart-with-mixed-multipart-request-spring-mvc-3-2
https://github.com/swagger-api/swagger-ui/issues/6462

- [ ] [Set up project integrations](https://git-1-fk.cocone.jp/app-center/app-center-server/-/settings/integrations)

- [ ] [Set up project integrations](https://git-1-fk.cocone.jp/app-center/app-center-server/-/settings/integrations)

test

# 마크다운 문법 예시

## 제목

# 제목 1

## 제목 2

### 제목 3

#### 제목 4

##### 제목 5

###### 제목 6

## 강조

**굵은 글씨**  
_기울임 글씨_  
~~취소선~~

## 리스트

### 순서가 없는 리스트

- 항목 1
- 항목 2
  - 하위 항목 2.1
  - 하위 항목 2.2
- 항목 3

### 순서가 있는 리스트

1. 첫 번째 항목
2. 두 번째 항목
   1. 하위 항목 2.1
   2. 하위 항목 2.2
3. 세 번째 항목

### 체크리스트

- [ ] 체크리스트 항목 1
- [x] 체크리스트 항목 2 (완료)

## 코드

### 인라인 코드

여기에 `인라인 코드`가 있습니다.

### 코드 블록

## 링크

[구글](https://www.google.com)

## 이미지

![테스트 이미지](https://via.placeholder.com/150)

## 인용

> 이것은 인용문입니다.

## 표

| 헤더 1   | 헤더 2   | 헤더 3   |
| -------- | -------- | -------- |
| 데이터 1 | 데이터 2 | 데이터 3 |
| 데이터 4 | 데이터 5 | 데이터 6 |

## 수식

여기서는 수학 수식을 표현할 수 있습니다:  
$E = mc^2$

## 줄 바꿈

줄 바꿈을 원할 때는 두 번 Enter를 누르세요.

첫 번째 줄입니다.  
두 번째 줄입니다.

## 수평선

---

## 주석

<!-- 이것은 주석입니다. -->
