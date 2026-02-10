---
title: MySQL Performance Optimization
published: true
description: Testing a post in a category subfolder
tags: database, rdb, mysql, optimization
cover_image:  
series:
---



im gonna show problem and performence what i handle big data on table 


i create table and that put in snowflake_id 
the table name is article
so create 12 mliun data on article table and then check this performence


![NotionImage](https://qlqjs674.notion.site/image/attachment%3Ab3255d34-be87-4731-b9fb-c7612854e659%3Aimage.png?table=block&id=245930ff-582f-8045-bc47-fb1ca5fd58d0&spaceId=6ab3efe6-44b5-4e5c-9d86-56543fb7f59d&width=660&userId=&cache=v2)





select * from article where board_id = 1 order by created_at desc limit 30 offset 90;


![NotionImage](https://qlqjs674.notion.site/image/attachment%3Aec33d6fc-1cad-45e0-8622-d7dab0643452%3Aimage.png?table=block&id=245930ff-582f-801d-83e0-d2c98a439051&spaceId=6ab3efe6-44b5-4e5c-9d86-56543fb7f59d&width=1420&userId=&cache=v2)

i guess more good computer get better result but mine spend 27 sec

so is very slow its not usable code so how to handle this problem





create index idx_board_id_article_id on article(board_id asc,
article_id desc);

![NotionImage](https://qlqjs674.notion.site/image/attachment%3A200066f9-3a18-435b-ac7c-c1ce7344bf8a%3Aimage.png?table=block&id=245930ff-582f-80f0-86c2-de82a18d4646&spaceId=6ab3efe6-44b5-4e5c-9d86-56543fb7f59d&width=1420&userId=&cache=v2)


![NotionImage](https://qlqjs674.notion.site/image/attachment%3Aa13e547f-933a-414f-8cce-ab5f3e3092c7%3Aimage.png?table=block&id=245930ff-582f-8061-b0e1-f0159d88a86d&spaceId=6ab3efe6-44b5-4e5c-9d86-56543fb7f59d&width=1420&userId=&cache=v2)


![NotionImage](https://qlqjs674.notion.site/image/attachment%3A5daa5247-e169-4d38-b962-ee2bcc6b7328%3Aimage.png?table=block&id=245930ff-582f-8007-ba77-f9a2b364921f&spaceId=6ab3efe6-44b5-4e5c-9d86-56543fb7f59d&width=1420&userId=&cache=v2)


so i cheked how much spend time and key and search type
this is meaning it work but is it okay? is that solved problem because we create index 

the answer is No 
im gonna show you if i change offset value


![NotionImage](https://qlqjs674.notion.site/image/attachment%3A8c2741c5-f9ee-428e-93eb-17d790823e4e%3Aimage.png?table=block&id=245930ff-582f-8039-9a45-f1750d5e3600&spaceId=6ab3efe6-44b5-4e5c-9d86-56543fb7f59d&width=1420&userId=&cache=v2)


its too late so i checked queryplan but notthing to change

mysql> explain select * from article where board_id = 1 order by article_id desc limit 30 offset 1499970;

![NotionImage](https://qlqjs674.notion.site/image/attachment%3A61aac8ce-2e4d-4901-a7a5-29246fd66651%3Aimage.png?table=block&id=245930ff-582f-8099-a66d-c13549d23460&spaceId=6ab3efe6-44b5-4e5c-9d86-56543fb7f59d&width=1420&userId=&cache=v2)



mysql은 
innodb 가 스토리지 엔진으로서 default 로 들어있다
andthen 

트랜잭션, 외래키, 충돌방지, 장애복수
4개의 기능이 특징이라고한다 

and then innodb is clusterd index primary key

그래서 article_id 를기준으로 하는 조회의 경우 프라이머리키를 이용한 조회라면 clusterd index가 자동으로 생성된다

so if you look this picktuer this is very fast
and so why is it so fase?

![NotionImage](https://qlqjs674.notion.site/image/attachment%3Ac2494fda-ee12-4a5e-867b-fa2dfed50b41%3Aimage.png?table=block&id=245930ff-582f-8035-8155-dea1c357a6ff&spaceId=6ab3efe6-44b5-4e5c-9d86-56543fb7f59d&width=1420&userId=&cache=v2)

because we use primary key 
we don't create but automaticaly primary key have clusterd index on innodb

![NotionImage](https://qlqjs674.notion.site/image/attachment%3A9b812d3b-1fdd-4086-b85a-72ef47ef1a13%3Aimage.png?table=block&id=245930ff-582f-8051-8f80-ed5c4e18beb8&spaceId=6ab3efe6-44b5-4e5c-9d86-56543fb7f59d&width=1420&userId=&cache=v2)


if we create index when we create call secondary index or non-clousterd index

leafnode have index column data and pointer to access clusterd index

세컨더리 인덱스는 클러스터드 인덱스와 관계하기때문에

리프노드에서 세컨더리 인덱스에 저장된 컬럼을 찾은후 클러스터드 아이디와 매칭해서 찾는다


아래 같은 경우에는 offset까지 도달하는데 계속해서 clusterd_index와 secondry index를 확인해야 한다 왜냐하면 order by가 들어가있기때문이다
select * from article where board_id = 1 order by article_id desc limit 30 offset 1499970;

1. WHERE board_id = 1 에 맞는 row들을 idx_board_id_article_id 인덱스를 통해 순서대로 스캔
2. article_id DESC로 정렬된 순서를 유지하며 row들을 하나씩 가져옴
3. OFFSET 개수만큼 버림 (1499970개 스킵)
4. 그 다음 LIMIT 30개만 SELECT 결과로 반환

즉, 처음부터 1499970개의 row를 순차적으로 읽고 버린 뒤, 그 다음 30개를 리턴하는 구조입니다.
offset 지옥이라고 한다


그래서 실무에선 어떻게하느냐 
keyset pagination) 또는 Seek method 라는 방식으로 offset없이 필요한 부분만 사용한다

-- 첫 요청
SELECT * FROM article 
WHERE board_id = 1 
ORDER BY article_id DESC 
LIMIT 30;

-- 다음 요청
SELECT * FROM article 
WHERE board_id = 1 
  AND article_id < {이전 마지막 article_id}
ORDER BY article_id DESC 
LIMIT 30;


covering index라는게 있다
index만으로 모든 쿼리의 데이터를 처리할수있는 index이며
clusterd index없이 secondary index만으로 쿼리 가능한 index를 말한다 


하지만 offset이 커지고 그 기능이 필요하다면 다른 방식으로 해결하나
년단위로 스킵한다던가 테이블에 파티션을 만들어 정보를 분리하는등
원래 정보량 자체가 많다면 이런식으로 해결하는것도 방법이다

혹은 정책으로 해결하는경우도있다
저렇게 오래된 이전 데이터를 추출한는것이 정상적인 유저가 아니라고 판단하여 제한 혹은
범위 검색등을 제공하는 방법이 있다

논리적으로 무한스크롤 같이 뒷페이지로 가도 균등한 조회속도를 낼술있지만 이렇게 많은 정보량이 있는경우 채택할 방법이 아닐수있다


페이징방식을 무한스크롤으로 할경우 

신규로 페이지가 만들어지거나 삭제되면 조회할때 중복 혹은 누락이 발생할수있다
무한스크롤은 마지막에 부른데이터를 기점으로 id를 기반으로 호출한다




Find all valid combinations of k numbers that sum up to n such that the following conditions are true:

Only numbers 1 through 9 are used.
Each number is used at most once.
Return a list of all possible valid combinations. The list must not contain the same combination twice, and the combinations may be returned in any order.
