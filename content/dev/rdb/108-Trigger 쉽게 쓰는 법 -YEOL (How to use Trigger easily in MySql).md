---
title: "Trigger 쉽게 쓰는 법 (How to use Trigger easily in MySql)"
labels: ["DB","rdb","trigger","mysql","sql"]
published: false
date: 2021-10-29T18:10:46+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 108
tistoryUrl: "https://yeolceo.tistory.com/108"
tistoryCategory: "DB/rdb"
tistoryTags: ["trigger","mysql","sql"]
tistoryPostedAt: "2021-10-29 18:10:46"
language: ko
bloggerPostId: "8980318432774771810"
---
**plz select language to right side menu.**

**Trigger 뜻**  
**명사 -> 방아쇠, 계기**  
**동사 -> 촉발시키다, 작동시키다**

**DB에서 Trigger란 query를 등록하고 insert, update, delete 같은 문장이 실행될 때** 

**등록한 Query를 작동시키는 기능입니다.**

**트리거 등록 및 동작 순서**

**1\. Trigger를 등록할 테이블 선정.**

**2\. Table에 Trigger와 등록할 Query를 만들어줍니다**

**3\. Trigger가 등록된 Table에서 insert, update, delete Query를 실행합니다.** 

**4\. 해당 Table에 Query가 실행될 때 Trigger에 등록한 Query를 작동시킵니다.** 

**Example 1**

**Table을 만들어줍니다. 학생 정보 Table과 학생의 시험 점수 Table입니다.**

```html
CREATE TABLE USER_INFO
(
	`NO`                     INT           	NOT NULL    AUTO_INCREMENT COMMENT 'auto increase', 
	`USER_ID`              	 VARCHAR(10)    NOT NULL    COMMENT 'USER ID', 
	`USER_NAME`              VARCHAR(10)    NOT NULL    COMMENT 'USER NAME', 
 	`ALL_SCORE`              INT	        NULL DEFAULT	0   COMMENT 'TOTAL SCORE', 
	CONSTRAINT PK_ PRIMARY KEY (NO)
);

CREATE TABLE GRADE_INFO
(
	`NO`                    INT       	NOT NULL    AUTO_INCREMENT COMMENT 'auto increase', 
	`USER_ID`               VARCHAR(10)    	NOT NULL    COMMENT 'USER ID', 
	`TEST`                  VARCHAR(10)     NOT NULL    COMMENT 'SUBJECT', 
	`SCORE`              	INT             NOT NULL    COMMENT 'SCORE',
	CONSTRAINT PK_ PRIMARY KEY (NO)
);
```

**Test를 위해 학생 정보를 넣어줍니다.**

```html
INSERT INTO USER_INFO(USER_ID, USER_NAME) VALUES('950814', 'YEOL');
```

**학생정보가 잘들어갔는지 확인해줍니다.**

```html
SELECT * FROM USER_INFO;
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/108/img.webp)

**이제 Trigger를 등록하겠습니다.** 

```html
DELIMITER $$
CREATE TRIGGER TRIGGER_USER_INFO
AFTER INSERT ON GRADE_INFO
FOR EACH ROW
BEGIN
 		IF NEW.USER_ID = '950814' THEN
        		UPDATE USER_INFO SET ALL_SCORE = ALL_SCORE + NEW.SCORE WHERE USER_ID = '950814';
 		END IF;
END; $$
DELIMITER ;
```

**DELIMITER : 구분 기호를 뜻하며 Trigger의 시작과 끝을 구분하기 위한 기호입니다. 구분 기호는 $$, // 등이 가능합니다.**

**CREATE TRIGGER (NAME) : 선언하는 Trigger의 이름입니다.**

**AFTER INSERT ON (Trigger를 등록할 테이블) : 해당 Table에 INSERT 된 후에 Trigger가 동작한다는 의미입니다.**  
**만약 BEFORE UPDATE ON  MY\_TABLE 이렇게 있다면 MY\_TABLE에서 UPDATE가 일어난다면 UPDATE 하기 전에**  
**Trigger를 동작합니다.** 

**FOR EACH ROW  영어 그대로 Table의 각 row에 다 적용된다는 의미입니다.** 

**UPDATE, DELETE에 해당하는 구문은 기존에도 WHERE 없이 실행하면 모든 row에 적용되기 때문에 FOR EACH ROW는 MySql에서 구문상 필수적으로 넣는다고 개념을 이해하시면 될듯합니다.**   
**(stackoverflow 참조입니다)** 

```html
INSERT INTO GRADE_INFO(USER_ID, TEST, SCORE ) VALUES('950814', 'ENGLISH', 88);
```

**자 이제 Trigger가 적용되었고 값을 넣어줍니다.**

```html
SELECT * FROM USER_INFO;
```

**INSERT가 GRADE\_INFO에 된 후 Trigger로 인해 USER\_INFO에 값이 입력되었다면 완성입니다.** 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/108/img_1.webp)

**Trigger 쉽게 쓰는 법을 올려봤습니다. 성실한 코딩 하세요.**
