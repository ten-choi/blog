---
title: "AWS Summit Notes"
labels: ["Archive"]
published: true
date: 2023-10-06T10:39:30+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 192
tistoryUrl: "https://yeolceo.tistory.com/192"
tistoryCategory: ""
tistoryTags: []
tistoryPostedAt: "2023-10-06 10:39:30"
language: en
bloggerPostId: "5895658106992634740"
---
aws summit log  
d  
1.   
A startup's case study: serverless SaaS data processing and building a data warehouse  
Community section  
Athlete? - the company name?  
BEFORE  
The initial architecture measured API usage on ECS and updated the DB on every API call,  
and failure cases were getting dropped (see photo)  
AFTER  
They switched to Amazon Athena, an interactive query service that lets you analyze S3 data with standard SQL (see photo). They said the reason was that per-query pricing is cost-efficient.  

Usage measurement flow  
Create data stream -> load access logs ->  

I have a capture of the initial architecture  
Why they chose AWS Athena  
It's serverless, you're only billed for the data you scan, and it suits batch jobs over long time ranges  
All of their AWS infra is set up with CDK in Python  
The destination is set to Firehose; once data piles up it's loaded into S3 as logs, also via CDK  

Speaker works at the ad-tech startup MADUP  
Agenda: explaining large-scale data collection, loading, and consumption  
Transactions, distribution keys, sort keys  
Couldn't you use TRUNCATE instead of DELETE? They said TRUNCATE behaves differently from a regular query  
Redshift compresses data when storing it  
A lot of their Redshift usage goes to a single ETL job  
RA3 gets up to 10x faster with AQUA  
Redshift can share data across clusters  
How to manage data: if you use Redshift Serverless, you must control and manage RPUs  
Careful: if you don't end a transaction, you keep getting billed while the connection is open  
Because of capacity issues, some of it has to be covered by Athena  
MADUP is working out how to use Athena well  

2.  
Data sharing and utilization: three secret weapons for company-wide data governance  
Intermediate tech 2  
Yoon-gun Kim, analytics business development at AWS  
Most companies think they need to become data-driven  
What if we solved data problems with governance software?  
Using governance tools doesn't solve the problem by itself  
What matters is that governance accelerates the data community  

No data owners: whether it's a data warehouse or a data lake, nobody owns the data in the infra  
When data quality drops, the consumers of that data feel the pain  
\-> lack of data governance  
What to check is data ownership, so how do you solve that?  
A marketplace for trading data -> once data becomes a product, ownership follows  
What does that even mean?  
Sung-won Park's solution  
Building a data mesh architecture  

What's a data mesh?  

Data mesh principles  
Data producers  
Productizing users-data-tools  
Data can be seen as a kind of product; it says APIs, SQL, reports. What's "reports"?  

Self-serve data infrastructure  

TODO: analyze and write up AWS Lake Formation and governance  

Jae-won Jung, Coupang data platform team  
Why did they adopt self-service EMR, and what governance did they build?  

The term "data lake" keeps coming up; this gets stored in the data warehouse  

Roles of the data platform: data infrastructure, core data, data intelligence  
Hive tables, Apache Ranger, permission management (built in-house)  
What's HDFS? Apparently temporary data and staging data go there  
For compute they use Amazon EMR and EKS, plus a DW cluster  
Hive, Spark - data processing engines?  
For scheduling, think of it as Airflow only  

Orca, their own tool modified from Netflix's Genie  
What's Hue?  
For messaging/monitoring they use Slack, Prometheus, Grafana  

Bottleneck  
SLA isn't guaranteed  

Portal API, EMR API?  
What's a Hive metastore?  

Governance split into four: security, cost estimation, lifecycle, resource utilization  
EMR keeps running unless you shut it down yourself, so it needs managing  
Transient clusters, static clusters  
Spark streaming job?  

3  
HashiCorp security policies  

4.   
12 architectures  
What is cloud native?  

Was it built reliably? The 6 we just saw  
Check whether it's well-architected through the pillars and lenses  
Workload?  
Migrating workloads to cloud native - what does that mean?  
Amazon SNS - there's a message broker  
Strangler fig pattern?  
ElastiCache, EventBridge
