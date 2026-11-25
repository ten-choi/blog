---
title: "Snowflake vs Databricks: Comparing Cloud Data Platforms"
labels: ["Database","OLAP","Snowflake","Databricks","Data Warehouse","Data Lakehouse","Archive"]
published: true
date: 2024-12-25T12:22:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "2858720344282997301"
source: "archive"
archivePath: "_archive/dev/database/Snowflake와 Databricks.md"
---




What are these?

Snowflake and Databricks are both cloud-based data platforms. They're completely different in nature from traditional OLTP databases (things like Oracle and MySQL). Simply put, they're platforms built specifically for "storing data and analyzing it."

Starting with the basics
OLTP vs OLAP
Category	OLTP	OLAP
Purpose	Transaction processing	Analysis/aggregation
Example query	"Process payment for this order"	"Regional sales trends over the past 3 years"
Typical DBs	Oracle, MySQL, PostgreSQL	Snowflake, Databricks, BigQuery
Data volume	GBs to TBs	TBs to PBs
