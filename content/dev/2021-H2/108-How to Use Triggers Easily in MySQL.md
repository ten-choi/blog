---
title: "How to Use Triggers Easily in MySQL"
labels: ["DB","rdb","trigger","mysql","sql","Archive"]
published: true
date: 2021-10-29T18:10:46+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 108
tistoryUrl: "https://yeolceo.tistory.com/108"
tistoryCategory: "DB/rdb"
tistoryTags: ["trigger","mysql","sql"]
tistoryPostedAt: "2021-10-29 18:10:46"
language: en
bloggerPostId: "8980318432774771810"
---
**Meaning of "trigger"**  
**Noun -> the trigger of a gun; something that sets things off**  
**Verb -> to set off, to activate**

**In a database, a trigger is a feature where you register a query, and when a statement like insert, update, or delete runs,** 

**the registered query is fired.**

**How triggers are registered and run**

**1\. Pick the table to register the trigger on.**

**2\. Create a trigger with the query to register on that table.**

**3\. Run an insert, update, or delete query on the table with the trigger.** 

**4\. When that query runs on the table, the query registered in the trigger fires.** 

**Example 1**

**Create the tables: a student info table and a student exam score table.**

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

**Insert a student record for testing.**

```html
INSERT INTO USER_INFO(USER_ID, USER_NAME) VALUES('950814', 'YEOL');
```

**Check that the student record went in.**

```html
SELECT * FROM USER_INFO;
```

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/108/img.webp)

**Now let's register the trigger.** 

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

**DELIMITER: a separator symbol that marks where the trigger starts and ends. You can use $$, //, and so on.**

**CREATE TRIGGER (NAME): the name of the trigger you're declaring.**

**AFTER INSERT ON (table to register the trigger on): the trigger fires after an INSERT on that table.**  
**If it said BEFORE UPDATE ON MY\_TABLE instead, then when an UPDATE happens on MY\_TABLE, the trigger fires**  
**before the UPDATE.** 

**FOR EACH ROW means just what it says: it applies to each row of the table.** 

**UPDATE and DELETE statements already apply to every row when run without a WHERE clause, so you can think of FOR EACH ROW as something MySQL simply requires syntactically.**   
**(Based on Stack Overflow.)** 

```html
INSERT INTO GRADE_INFO(USER_ID, TEST, SCORE ) VALUES('950814', 'ENGLISH', 88);
```

**The trigger is in place, so now insert a value.**

```html
SELECT * FROM USER_INFO;
```

**If the trigger updated USER\_INFO after the INSERT into GRADE\_INFO, you're done.** 

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/108/img_1.webp)

**That's how to use triggers the easy way. Happy coding.**
