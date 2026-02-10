---
title: My English Learning Journey
date: 2025-05-30
published: true
description: My journey learning English from elementary school through university, and continuing in Korea and Japan
tags: english, language-learning, study-abroad, personal-development, education
cover_image: https://upload.wikimedia.org/wikipedia/commons/thumb/a/ae/Flag_of_the_United_Kingdom.svg/1200px-Flag_of_the_United_Kingdom.svg.png
series: Language Learning Series
---

i

prabably i can speak noramal talk but business level is differnce 
so i should practice how do i do
when i search hire process x hireing process in japan
i think x is big company and it's fine to think that is normal process

1. CV Reviewing 
2. Coding Test & System Design (90min)
3. Team Fit & Technical Round (60min)
4. Offer


so i think i start how to response cv reviwing
Top 10 Behavioral Software Engineering Interview Questions - Expoenet youtube


why thay ask 
https://www.linkedin.com/pulse/27-most-common-job-interview-questions-answers-jeff-haden/

i should tell my skill in english 
https://roadmap.sh/questions/ 

10 quistion youtube
https://www.youtube.com/watch?v=T25I2FQ9Mok


1. introduce my self

i wrok about 6years as backend engenner, 
one of my personlity is i love effitiont.
when i do work or somthting

when i did project in company i 나는 효율적인 부분들을 많이 어필했다
one of the big part is talk about infra service aws
team working and communicate

because this compony devide work permission so most of backend engineer can't handle aws.
but when we need aws setting we have to request infra team.

I have designed, developed, and deployed various services.
I value a logical and structured approach to development. From defining how to split domains to clearly documenting requirements from planning or during collaboration, I emphasize breaking down tasks effectively. As the scale of development increases, this clarity leads to greater efficiency. I also place strong importance on writing clean code.

I believe developers directly contribute to a company’s economic efficiency. A simple example: if a server costing 100 million KRW is optimized by just 10%, it results in a 10 million KRW cost saving. My goal is to build high-value systems through traffic optimization, data communication analysis, and continuous refactoring—especially as user traffic grows.

I also believe that recognizing the value of consistent effort plays a key role in fostering a culture of mutual growth.

That’s why I regularly document new experiences and technical challenges on my blog. By sharing solutions and proposing problem-solving approaches, I aim to provide constructive feedback and help guide team members toward better directions.





--------------------




## Describe how you would implement a full-text search in a database.

You can use the native full-text search functionality of a database, such as MySQL, Postgre or even ElasticSearch.

However, if you want to implement it yourself, the steps would be:

Preprocessing the text data to be searched and normalizing it by applying tokenization, stemming and removing stop words.

Then, implement an inverted index, somehow relating each unique word to the records that contain that word.

Create a search UI and normalize the input from the user in the same way the text data was normalized.

Then, search for each word in the database.

Sort the results by implementing a scoring logic based on different aspects, such as word frequency.



-----------------
Advanced

## What is database replication, and how can it be used for fault tolerance?

Database replication implies the replication of data across multiple instances of the same database. In this scenario, there is usually one database that’s acting as a master to all clients that are connecting it, and the rest act as “slaves” where they simply receive updates on the data being changed/added.

The two main implications of this in fault tolerance are:

A database cluster can withstand problems on the master server by promoting one of the slaves without losing any data in the process.

Slaves can be used as read-only servers, increasing the amount of read requests that can be performed on the data without affecting the performance of the database.

## Describe the use of blue-green deployment strategy in backend services

The blue-green strategy involves having two identical production environments, having one of them serving real traffic while the other is getting ready to be updated with the next release or just idle, waiting to be used as a backup.

