---
title: "Snowflake와 Databricks: 클라우드 데이터 플랫폼 비교"
labels: [데이터베이스, OLAP, Snowflake, Databricks, 데이터 웨어하우스, 데이터 레이크하우스]
published: 
date: 
readerComments: "ALLOW"
bloggerPostId: 
---




이건뭘까

Snowflake와 Databricks는 둘 다 클라우드 기반 데이터 플랫폼입니다. 전통적인 OLTP용 DB(Oracle, MySQL 같은 것)와는 성격이 전혀 달라요. 쉽게 말해 "데이터를 쌓아두고 분석하는 용도" 에 특화된 플랫폼입니다.

기본 개념부터
OLTP vs OLAP
구분	OLTP	OLAP
목적	거래 처리	분석/집계
예시 쿼리	"이 주문 결제해줘"	"지난 3년간 지역별 매출 트렌드"
대표 DB	Oracle, MySQL, PostgreSQL	Snowflake, Databricks, BigQuery
데이터 양	수GB~수TB	수TB~수PB
