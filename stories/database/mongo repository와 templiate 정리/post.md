# 코틀린에서 몽고 디비를 orm 스럽게 사용하는법

코틀린에서 몽고db를 사용했습니다
typescript나 python을 사용했던 orm경험이 있고 java, kotlin에서는 jpa와 queryDsl 을 사용했기때문에 orm스럽게 동작했습니다
하지만 mongo에서 사용할때 jpa형식을 사용하는경우에는 문제가없었지만 application등을 사용하는경우 좀더 orm스럽게 사용하고 글을 남기기로했습니다

**몽고란**
mongodb는 nosql db로 문서지향모델을 사용하여 json형식으로 데이터를 저장합니다 sdfㅇ
유연한 스키마를 제공하기때문에 데이터의 구조변경이 쉽고
자동샤딩을 통해 높은성능과 대용량 데이터 처리에 용이합니다

**Tech stack**
kotlin 1.9
spring 3.3
intellij
mongodb

# 간단하게 인스톨후 사용

코틀린에서 mongo를 사용할때 주로 사용되는 2가지 방법입니다
MongoRepository 를 사용하기위해 kotlin spring 환경을 구성해줍니다
mongorepository 디펜던시를 추가해줍니다  
`implementation("org.springframework.boot:spring-boot-starter-data-mongodb")`

아래와 같이 추가했으면 main을 실행할 구조를 확인합니다
실행테스팅을 해봅시다

```Kotlin

```

## MongoRepository

MongoRepository는 Spring Data MongoDB의 인터페이스로, MongoDB와 쉽게 상호작용할 수 있게 도와줍니다. 주로 CRUD(Create, Read, Update, Delete) 작업을 간단하게 수행할 수 있습니다.
특징
높은 수준의 추상화: 메서드 이름만으로 쿼리를 생성할 수 있어 복잡한 쿼리를 작성할 필요가 없습니다.
생산성: 간단한 CRUD 요청이 많은 경우, 빠르게 개발할 수 있어 효율적입니다.
제한된 제어: 기본 CRUD 외에 복잡한 쿼리에는 제약이 있어 추가 작업이 필요할 수 있습니다.
파생 쿼리 지원: 메서드 이름에 따라 자동으로 쿼리가 생성됩니다.
@Query 주석: 필요에 따라 사용자 정의 쿼리를 주석을 통해 정의할 수 있습니다.

## MongoTemplate

MongoTemplate은 MongoDB와의 상호작용을 위한 더 세밀한 API를 제공합니다. 복잡한 쿼리가 필요할 때 사용됩니다.

특징
낮은 수준의 추상화: MongoDB 쿼리를 직접 작성해야 하므로, 세밀한 제어가 가능합니다.
완전한 제어: 쿼리 논리를 완벽하게 조정할 수 있어 필요한 대로 최적화할 수 있습니다.
복잡한 쿼리 지원: Aggregation, 인덱스 관리 등 다양한 기능을 지원합니다.
CRUD 외의 기능: 단순 CRUD 작업 이외에도 다양한 MongoDB 기능을 활용할 수 있습니다.

mongodb는 nosql db로 문서지향모델을 사용하여 json형식으로 데이터를 저장합니다 sdfㅇ
유연한 스키마를 제공하기때문에 데이터의 구조변경이 쉽고
자동샤딩을 통해 높은성능과 대용량 데이터 처리에 용이합니다

## mongoTemplate, mongoRepository 란

mongo를 사용할때 주로 사용되는 2가지 방법입니다

### MongoRepository

MongoRepository는 Spring Data MongoDB의 인터페이스로, MongoDB와 쉽게 상호작용할 수 있게 도와줍니다. 주로 CRUD(Create, Read, Update, Delete) 작업을 간단하게 수행할 수 있습니다.
특징
높은 수준의 추상화: 메서드 이름만으로 쿼리를 생성할 수 있어 복잡한 쿼리를 작성할 필요가 없습니다.
생산성: 간단한 CRUD 요청이 많은 경우, 빠르게 개발할 수 있어 효율적입니다.
제한된 제어: 기본 CRUD 외에 복잡한 쿼리에는 제약이 있어 추가 작업이 필요할 수 있습니다.
파생 쿼리 지원: 메서드 이름에 따라 자동으로 쿼리가 생성됩니다.
@Query 주석: 필요에 따라 사용자 정의 쿼리를 주석을 통해 정의할 수 있습니다.

### MongoTemplate

MongoTemplate은 MongoDB와의 상호작용을 위한 더 세밀한 API를 제공합니다. 복잡한 쿼리가 필요할 때 사용됩니다.

특징
낮은 수준의 추상화: MongoDB 쿼리를 직접 작성해야 하므로, 세밀한 제어가 가능합니다.
완전한 제어: 쿼리 논리를 완벽하게 조정할 수 있어 필요한 대로 최적화할 수 있습니다.
복잡한 쿼리 지원: Aggregation, 인덱스 관리 등 다양한 기능을 지원합니다.
CRUD 외의 기능: 단순 CRUD 작업 이외에도 다양한 MongoDB 기능을 활용할 수 있습니다.

## Examine

먼저 최초 의 방식은 아래와 같습니다 아래처럼 id, collection을 정의해서 사용하는 것입니다

```kotlin
object MongoField {
    const val ID = "_id"
    const val STUDENT_ID = "student_id"
    const val EXAM_GRADE_ID = "exam_grade_id"
    const val NAME = "name"
}
object MongoCollection {
    const val STUDENT = "student"
    const val EXAM_GRADE = "exam_grade"
}
```

그러면 document를 설정할때 아래처럼 사용할수있습니다

```kotlin
@Document(collection = MongoCollection.STUDENT)
data class Student(
    @Id val id: ObjectId = ObjectId.get(),
    @Field(MongoField.NAME) var name: String,
    @Field(MongoField.EMAIL_ADDRESS) var emailAddress: String,
    @Field(MongoField.IS_ACTIVATED) val isActivated: Boolean = true,
    @Field(MongoField.CREATED_AT) var createdAt: LocalDateTime = LocalDateTime.now(),

    val examGrade: ExamGrade? = null
)
```

위와같이 할경우 모든 String을 직접 입력하는것이 아닌 별도로 입력해놓은 값을 가져오기때문에 휴먼에러가 일어날 가능성이 줄어든다

그리고 interface쪽으로 가면 일반적인 find의 경우 mongoRepositorty가 지원해주기때문에 문제가없다

```kotlin
interface StudentRepository : MongoRepository<Student, ObjectId>{
}

```

`StudentRepository.findAll()`이런식으로 코드를 사용하면 아주 간편하다.
하지만 mongo에서도 join을 해야할 가능성이 존재한다.

그리고 이경우`@Annotation`을 지원해주고 이것을 사용할수있다
하지만 이것은 함정과도 같다 이것을 쓰는순간 String의 늪에 빠지게될것이다
link https://www.mongodb.com/ko-kr/docs/drivers/kotlin/coroutine/current/fundamentals/aggregation/

그렇기 때문에 mongoTemplate을 사용하여 최대한 문자열 사용을 없에보려고 시도했다
먼저 아래처럼 interface에 참조하는 방식을 사용하여 mongoTemplate을 사용한 클래스를 만든다
그리고 확장함수 `snakeToCamel()`를 사용했다. 케이스를 바꿔주기때문에 ` val examGrade: ExamGrade? = null` 이곳에 자연스럽게 값을 넣을수있다.

```kotlin

@Repository
class StudentAggregationRepositoryImpl : StudentAggregationRepository {
    @Autowired
    private lateinit var mongoTemplate: MongoTemplate

    override fun findByStudentIdWithExamGrade(
        studentId: ObjectId,
    ): Optional<Student> {
        val matchStage = Aggregation.match(
            Criteria.where(MongoField.ID).`is`(studentId)
        )
        val lookupStage = Aggregation.lookup(
            MongoCollection.EXAM_GRADE, // collection name
            MongoField.ID, // localField
            MongoField.STUDENT_ID, // foreignField
            MongoCollection.EXAM_GRADE.snakeToCamel() // as
        )
        val unwindStage = Aggregation.unwind(MongoCollection.EXAM_GRADE.snakeToCamel(), true)
        val aggregation = Aggregation.newAggregation(
            matchStage,
            lookupStage,
            unwindStage
        )
        val aggregationResults: AggregationResults<Student> =
            mongoTemplate.aggregate(
                aggregation, MongoCollection.STUDENT, Student::class.java
            )
        return Optional.ofNullable(aggregationResults.mappedResults.firstOrNull())
    }
}

```

그리고 아래처럼 참조하면 동일한 방식인 `StudentRepository` 만 사용하는것으로 자연스럽게 aggregation을 사용하기때문에 별도의 선언이 필요가없어진다

```kotlin
interface StudentRepository : MongoRepository<Student, ObjectId>, StudentAggregationRepository {
}

interface StudentAggregationRepository {
    fun findByStudentIdWithExamGrade(
        studentId: ObjectId,
    ): Optional<Student>
}

```

mongo의 annotation을 하는경우에는 string을
공식문서에는 변수형태로 나오지만 repository를 사용하는경우에 aggregation을 annotation형태로 사용한다면
모든 입력값을 String형태로 입력한다. 그래서 문자열하나 잘못입력하면 이것도문제가 될수있다

https://docs.spring.io/spring-data/mongodb/reference/mongodb/aggregation-framework.html

따라서 가능하면 문자열을 최대한 없에고싶었다

먼저 aggregation interface를 하나더 만들어준다

그리고 aggregation에 맞는 MongoTemplate을 하나추가한다

match, group등을 필요한곳에 사용한후 newAggregation으로 결합한다

```kotin

interface AppCollaboratorRepositoryAggregation {
    fun findByIdInGroupByAppCollaboratorRole(
        ids: List<ObjectId>
    ): List<String>

    fun findAllByAppIdWithUser(
        appId: ObjectId
    ): List<AppCollaborator>


    fun findAllByOrganizationCollaboratorIdsWithAppByName(
        organizationCollaboratorIds: List<ObjectId>,
        appName: String
    ): List<AppCollaborator>

}



@Repository
class AppCollaboratorRepositoryAggregationImpl : AppCollaboratorRepositoryAggregation {
    @Autowired
    private lateinit var mongoTemplate: MongoTemplate
    override fun findByIdInGroupByAppCollaboratorRole(ids: List<ObjectId>): List<String> {
        val matchStage = Aggregation.match(
            Criteria.where(MongoField.ID).`in`(ids)
        )
        val groupStage = Aggregation.group(MongoField.APP_COLLABORATOR_ROLE)
        val aggregation = Aggregation.newAggregation(matchStage, groupStage)
        val results: AggregationResults<Document> = mongoTemplate.aggregate(
            aggregation, MongoCollection.APP_COLLABORATOR, Document::class.java
        )
        return results.mappedResults.map { it.getString(MongoField.ID) }
    }
}
```

이상 결과를 하면 마무리가 된다

위처럼 선언하면 mongoTemplate선언이 완료된다 이제 repository랑 template을 하나의 interface에서 사용하자

최초의 repositoryInterface에 상속하게되면 repository에서 전부 호출 가능하다
service layer에서 이중으로 호출할 필요가 없다

```kotin

interface BookingRepository :  MongoRepository<AppCollaborator, ObjectId>, BookingRepositoryAggregation {
    fun findAllById(id:ObjectId)
}
```

안타까운점은 BookingRepository class의 users는 user가 리스트가 된거기때문에
별도의 변수명을 추가할 오브젝트를 만들어야하고
참조변수명이 미리 설정한 값과 달라지게되면 해당 값을 호출하지 못하는 이슈가 발생한다

이부분에 대한 수정은 어떻게해야하나 고민중이다

저부분 이외에는 대체적으로 sequelize나 DjangoOrm처럼 사용할수있었기때문에 만족한다

만약 다른 더좋은 방법을 제시해줄수있는 사람이 있다면 댓글 바란다.

    ) {
    init {
        // 프로퍼티 이름을 문자열로 정의
        val nameCheck = "organizationCollaborator"
        nameCheck.to
        // 변수 이름 비교
        if (::organizationCollaborator.name != nameCheck) {
            throw IllegalArgumentException("변수 이름이 일치하지 않습니다.")
        }
    }

}

위처럼 init넣고 문자열 비교하면 체크는 되지만 개애바다 , 선언붕에서 선언과 동시에 name은 끌어올수없다 kotlin에서 서포트하지안흔ㄴ다고 한다
camelcase 를 사용하기 위해서는

object MongoCollectionCamel {
const val ORGANIZATION_COLLABORATOR = "organizationCollaborator"
const val APP_COLLABORATOR = "appCollaborator"
} 이런 코드를 만들었지만 차라리 함수를 만들어서 사용할때마다 camel을 적용하는게 훨신깔끔하다

그리고 결국 변수 그것도 하고싶어서 알아보는중이다
어노테이션 방법은 벨리드 개념으로 쓰이거나 써도 실행됬을때 바로 동작하는 개념으로 찾아봤지만 그런 방법은 찾을수없었다

aspect방법을 사용해 특정 어노테이션이 있는경우를 고려해봤지만 이경우도 애매했다

그래서 entity라는 패키지안의 모든 클래스에 필드명을 출력하는데
그중에서 어노테이션이 없는 필드만 출력하고 그필드들은 모두 mongocoleection의 케멀케이스 값중 하나일경우 문제가 없게 하는식으로 코드를 진행하려한다.
지금은 진행중이다.

캠퍼패니언 오브젝트나 다른것들을 테스팅 해봤다
컴패니언 오브젝트는 한번 실행되야 하기때문에 의도에 맞지않았다
