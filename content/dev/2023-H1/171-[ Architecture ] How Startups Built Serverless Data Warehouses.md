---
title: "[ Architecture ] How Startups Built Serverless Data Warehouses"
labels: ["Architecture","aws","Archive"]
published: true
date: 2023-05-14T16:20:01+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 171
tistoryUrl: "https://yeolceo.tistory.com/171"
tistoryCategory: "Architecture/architecture"
tistoryTags: ["architecture","KR","aws"]
tistoryPostedAt: "2023-05-14 16:20:01"
language: en
bloggerPostId: "3818010277294086786"
---
The first session I attended at AWS Summit was "Building Serverless SaaS Data Processing and a Data Warehouse"  
It covered how two companies solved technical issues by changing their logic or using AWS features

First company: Asleep  
A company that offers a SaaS service using AI models to accurately analyze sleep and provide personalized sleep services  

Before  
They said the initial architecture had 3 problems  
I don't remember the whole explanation, so I'm filling in the gaps with my own guesses  
\-> The gist is that the API requests users make through the client UI and the requests that store the sleep-analysis stream data both go through the same ELB, which causes the problems shown in the image below

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/171/img.webp)

After  
I don't remember the whole explanation, so I'm filling in the gaps with my own guesses  
\-> Sleep-analysis stream data coming in through the gateway is passed to Firehose, and once enough data accumulates, it's stored in an S3 bucket  
It looks like they use AWS Glue, a serverless ETL (Extract, Transform, Load) service, to transform the unstructured data and store it as a data source  
They said switching to storing the data compressed in Parquet format made things much more efficient

When the data source needs to be queried periodically, they seem to use AWS Athena for serverless queries  
They said the AWS infrastructure was managed with CDK  
Compared to before, both cost and operational overhead went down

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/171/img_2.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/171/img_3.webp)

Second company: MADUP  
Develops and operates a digital marketing automation solution  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/171/img_4.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/171/img_5.webp)

They wanted to collect and process large volumes of data to build a data warehouse  
They explained how data goes from Amazon Athena through Amazon Redshift Serverless to the teams that need it  
[https://aws.amazon.com/ko/blogs/korea/new-aqua-advanced-query-accelerator-for-amazon-redshift/](https://aws.amazon.com/ko/blogs/korea/new-aqua-advanced-query-accelerator-for-amazon-redshift/)  

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/171/img_6.webp)

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/171/img_7.webp)

They also walked through how they handle large-scale data

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/171/img_1.webp)

What helped me most here was seeing how usable serverless is  
AWS Glue, Athena, and Redshift are used this much in the startup scene?  
That tells me it's quite efficient, improves data reliability, and cuts costs
