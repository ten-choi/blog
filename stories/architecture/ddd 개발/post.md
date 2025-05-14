# Domain-Driven Design (DDD)

Domain-Driven Design (DDD) is a software development methodology focused on understanding and effectively modeling complex domains. Also known as domain-driven design, it emphasizes designing and developing software by concentrating on the domain while minimizing its complexity.

A domain refers to a set of important business concepts and rules. In DDD, the domain specifically refers to the business domain, which can be understood as a collection of related business operations. DDD focuses on these domains and structures software around domain models. In this post, we will explore the characteristics of DDD and its design approach.

Domain Model
A domain model represents the core concepts and rules of a domain as objects. While it conceptually represents the domain itself, the term "domain model" is also used to refer to the object model used when implementing the domain layer. It encapsulates business logic and is developed through collaboration with domain experts.

Key Characteristics
Understanding and effectively modeling complex domains for software design and development

The goal is to enable domain experts and developers to share and collaborate on domain knowledge to build and maintain the domain model.
Enhancing code readability and maintainability by clearly expressing business logic and important domain concepts

The software should accurately reflect real business operations, minimizing complexity while effectively implementing domain logic.
In essence, DDD focuses on the core domain and its functionalities, requiring a precise and well-structured domain model.

Why "Domain-Driven" is Commonly Mentioned in MSA
The term "domain-driven" is frequently discussed in Microservices Architecture (MSA) because MSA divides the system into domain-based services. This division helps achieve better fault tolerance and load balancing.

Strategic Design
Strategic Design is an approach for designing large-scale systems by dividing the overall system into multiple Bounded Contexts and defining their interactions.

A Bounded Context defines the scope in which a domain model is applied. Each Bounded Context consists of one or more domain models, which are designed to express and solve business requirements within that specific context. They can be modeled, developed, and deployed independently.

However, to ensure system-wide integration, Bounded Contexts must interact with each other through Context Mapping. Context Mapping is a technique that defines the boundaries and interactions between Bounded Contexts, utilizing specific patterns and agreements to integrate them effectively.

In DDD terminology:

Domain refers to the overall system design.
SubDomain represents subsets of the domain.
Bounded Context defines the contextual boundaries of these SubDomains.
Strategic Design uses Context Mapping to define boundaries between Bounded Contexts and applies various patterns like Shared Kernel, Customer/Supplier, and Conformist to facilitate common model sharing.

As a result, Strategic Design helps reduce system complexity, improve maintainability, and enhance collaboration between domain experts and developers. By accurately understanding and modeling business concepts, it ensures that the system aligns with real business requirements.

actical Design in Domain-Driven Design (DDD)
Tactical Design refers to the process of constructing a domain model within a Bounded Context in Domain-Driven Design (DDD). Within a Bounded Context, the domain model is specifically designed and implemented to address business requirements.

This approach involves a large domain consisting of multiple subdomains, each with distinct characteristics, which are implemented as services.

Tactical Design focuses on selecting and connecting the components of the main domain model. The key components include:

Key Components of Tactical Design

1. Layered Architecture
   A software architecture pattern that divides a system into multiple layers.
2. Value Object
   An object that represents a value within the software model.
   Unlike an entity, a Value Object does not have an identity but holds a state.
   It must be immutable, often encapsulating domain logic such as unit conversion or formatting.
3. Aggregate
   A logical unit that groups related entities and value objects together.
   It is accessed externally via the Aggregate Root, ensuring consistency and immutability within the aggregate.
4. Entity
   A domain object with a unique identity and mutable state.
   Entities include business logic that enables state changes.
   A typical example is a row in a database table.
5. Service
   A component that contains operations that do not naturally fit into domain objects.
6. Factories
   Classes or methods responsible for creating domain objects.
7. Repositories
   Components that provide an interface for storing, retrieving, and manipulating domain objects.
8. Domain Service
   A domain-level abstraction that encapsulates business logic.
   Used when domain logic cannot be naturally assigned to a specific entity.
   Typically defined as an interface, with its implementation used within the domain model.
   Tactical Design in DDD
   Tactical Design applies object-oriented programming principles and DDD techniques to build domain models that ensure consistency and maintainability.

By accurately reflecting domain complexity and properly defining object responsibilities and relationships, Tactical Design helps create a model that effectively expresses business logic.

It provides a concrete approach to implementing business requirements within a Bounded Context, ensuring that the domain model correctly represents business complexity while being understandable and maintainable.

Together with Strategic Design, Tactical Design is one of the core principles of Domain-Driven Design (DDD) and plays a crucial role in effective software modeling. 🚀

Soulution Space

Entitiy

- uuid this is have unique id
- Value Object
- status
-

Bounded Context
Aggregate

java blue book 

Domain-Driven Design (Domain-Driven Design)은 소프트웨어 개발 방법론 중 하나로, 복잡한 도메인을 이해하고 효과적으로 모델링하기 위해 사용되는 개발 철학과 방법입니다. 도메인 주도 설계라고도 부르는데, 도메인에 집중하며 도메인의 복잡성을 최소화하기 위해 소프트웨어를 설계하고 개발합니다.

도메인이란 비즈니스에서 중요한 개념과 규칙들의 집합을 의미합니다. DDD에서의 Domain은 비지니스 Domain인데, 이는 유사한 업무의 집합이라고 할 수 있습니다. DDD는 이러한 도메인에 집중하며, 도메인 모델을 중심으로 소프트웨어를 설계합니다. 이번 포스팅에서는 DDD의 특징과 디자인 설계방식을 알아보겠습니다.

도메인 모델 (Domain Model):
도메인 모델은 도메인의 핵심 개념과 규칙을 객체로 표현한 것을 말합니다. 도메인 자체를 표현하는 개념적인 모델을 의미하지만, 도메인 계층을 구현할 때 사용하는 객체 모델을 언급할 때에도 '도메인 모델'이란 용어를 사용합니다. 비즈니스 로직을 담고 있으며, 도메인 전문가들과의 협력을 통해 구축됩니다.

특징

1. 복잡한 도메인을 이해하고 효과적으로 모델링하여 소프트웨어를 설계하고 개발
   도메인 전문가들과 개발자들이 도메인을 공유하고 협력하여 도메인 모델을 구축하고 유지보수할 수 있도록 하는 것이 목표입니다.

2. 비즈니스 로직과 도메인의 중요한 개념들을 명확하게 표현하여 코드의 가독성과 유지보수성을 향상시키기 위함
   실제 비즈니스 동작을 잘 반영하고, 도메인의 복잡성을 최소화하면서도 효과적으로 도메인 로직을 구현해야 합니다.

즉, 핵심 도메인과 기능에 집중하고, 도메인의 모델을 정교하게 구축해야합니다.

MSA에서 에서 도메인 주도라는 말이 많이 나오는 이유는 도메인단위로 나누어 결국 이루고자 하는건 장애처리와 부하분산의 용이함을 위함이다

Strategic Design

Strategic Design은 큰 규모의 시스템을 구축할 때 전체 시스템을 여러 개의 Bounded Context로 나누고, 이들 간의 상호작용을 설계하는 것을 의미합니다.

여기서, Bounded Context 는 도메인 모델을 적용할 범위를 한정하는 개념입니다. 각 Bounded Context 는 한 개 또는 여러 개의 도메인 모델로 구성되며, 도메인 모델은 해당 Bounded Context 에서의 비즈니스 요구사항을 표현하고 해결하기 위해 설계됩니다. 독립적으로 모델링하고 개발할 수 있으며, 배포될 수도 있습니다.

그러나 시스템 전체적인 통합을 위해서는 Bounded Context 간의 상호작용과 컨텍스트 매핑(Context Mapping)이 필요합니다. 컨텍스트 매핑은 Bounded Context 간의 경계와 상호작용을 정의하는 기법으로, 상호작용을 위한 어떤 패턴과 약속을 만들어 두 개 이상의 Bounded Context를 통합하는데 사용됩니다.

Domain 은 큰 설계의 전체를 뜻하고, 각각의 부분 집합을 SubDomain 이라고 부릅니다. 이러한 SubDomain 의 문맥적 상황을 Bounded Context 라고 합니다.

Strategic Design 은 이러한 각 Bounded Context 들을 경계하기 위해 Context Mapping 이라는 기법을 사용하고, Bounded Context 간에는 공통된 모델을 공유하기 위해 Shared Kernel, Customer/Supplier, Conformist 등 다양한 패턴을 활용합니다.

결과적으로, Strategic Design 은 전체 시스템의 복잡성을 줄이고 유지보수성을 높이는데 도움을 주며, 도메인 전문가와 개발자 간의 소통과 협력을 강화합니다. 또한, 비즈니스 용어와 개념들을 정확히 이해하고 모델링함으로써 시스템이 실제 비즈니스 요구사항을 잘 반영할 수 있게 됩니다.

Tactical Design

Tactical Design (전술적 설계) 은 도메인 주도 설계 (DDD) 에서 Bounded Context 내부의 도메인 모델을 구축하는 단계를 말합니다. Bounded Context 내에서는 비즈니스 요구사항을 해결하기 위한 도메인 모델을 구체적으로 설계하고 구현합니다.

큰 집단 한 개(Domain)와, 그 안에 특징이 구별되는 여러 개의 집합(SubDomain)이 서비스로 구현되는 설계 방식입니다.

메인 모델의 구성요소들을 선택하고 연결하는 방법을 다루며, 주요 구성요소로는 Layered Architecture, Value Object, Aggregate, Domain Events, Factories, Repositories, Entity 등이 있습니다.

Layered Architecture (계층화 아키텍처)
소프트웨어 시스템을 여러 계층으로 구분하여 설계하는 아키텍처 패턴
Value Object (값 객체)
소프트웨어의 모델을 구성하는 수치에 대한 객체

엔티티와 달리 도메인 모델에서 상태를 가지는 객체이지만 식별자가 없는 객체

불변(Immutable)해야 하며, 단위 환산, 표현법 변경 등 다양한 도메인 로직을 가짐

Aggregate (집합체)

연관된 엔티티와 값 객체를 묶어 하나의 논리적 단위로 표현하는 개념

Aggregate Root를 통해 집합체 외부에서 접근 가능하며, 일관성을 유지하기 위해 불변성을 가짐

Service (서비스)
Domain Object에서 위치시키기 어려운 operation을 가지는 객체
Factories (팩토리)
객체를 생성하는 역할을 수행하는 클래스 또는 메서드
Repositories (리포지토리)
도메인 객체를 저장, 검색, 조작하는 인터페이스를 제공하는 객체
Entity (엔티티)
도메인 모델에서 가장 중요한 개념 중 하나로, 식별 가능하고 상태를 가지는 도메인 객체

고유한 식별자

엔티티의 상태는 변경될 수 있으며, 도메인 로직을 통해 상태를 변경하고 동작하는데 필요한 비즈니스 로직을 포함

대표적인 예로, DB에 있는 row들의 예가 있음

도메인 서비스(Domain Service)
도메인 모델의 행위를 추상화하고 도메인 로직을 수행하는 객체

특정 엔티티의 행위로 표현하기 어려운 도메인 로직을 캡슐화하는 역할

보통 인터페이스로 정의되며, 구현체는 도메인 모델 내부에서 사용

Tactical Design은 도메인 모델을 구현할 때 객체지향 프로그래밍 기법과 도메인 주도 설계의 기법들을 적절히 활용하여 모델의 일관성과 품질을 높이는데 중점을 두고 있습니다. 도메인의 복잡성을 잘 반영하고, 비즈니스 로직이 잘 표현되도록 객체의 책임과 협력 관계를 설계하는 것이 중요합니다.

또한, Bounded Context 내에서 비즈니스 요구사항을 구현하기 위한 구체적인 방법을 제시하고, 도메인 모델이 비즈니스 도메인의 복잡성을 잘 표현하고 이해할 수 있도록 도와줍니다. 전략적 설계와 함께 Tactical Design은 DDD의 핵심적인 구성요소이며, 효과적인 도메인 주도 설계를 위한 핵심 원리 중 하나입니다.

ddd 핵심 구성 어쩌구 하는거 의미없다고 본다 하는법부터 알고 뒤를 설명하자
머리좋은 사람들은 이해하고 실행한다면 나는
실행하고 이해하는편이다

왜 사용되는지 눈으로 보고 실행해보고 뜯어보면서 이해하는게 가장편하기때문이다

aggregate라는것도 결국 db에 데이터가 가기위해 예를 들면 배달이라는 행위가 일어났을때

다른domain끼리는 event로 전파하는 그 방식이다
