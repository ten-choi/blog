---
title: "api gateway pattern 분석"
labels: ["api gateway pattern", "architecture", "kr"]
date: 2023-05-04T22:51:00-07:00
bloggerPostId: "6916614068378448970"
published: true
originalUrl: "https://ten-logged.blogspot.com/2023/05/api-gateway-pattern.html"
---
api gateway pattern를 분석하자  

client와 microService 사이에서 매개체 역할을 하는 server다  
server가 4대인 하나의 service일 경우 각 server별 domain이 다를 것이다  
예를 들면 customer, order, delivery, review 이렇게 4대가 하나의 service를 위한 server들이라고 가정하자  
접속 가능한 client는 web과 mobile 2개라고 가정하자  

4가지 분석 유형

1\. domain을 분리한 4개의 server가 있다. 하지만 client에서는 한 번에 2종류 이상의 데이터를 받아야 한다.  
client에서 2개 이상의 api를 호출하여 결합해야 한다. 그러면 복잡성이 증가한다  
\-> gateway에서 필요한 데이터를 각 domainServer에 요청하고 client에 데이터를 반환하자  
delivery server에서 배달을 위해 주문한 상품을 알고 싶은 경우가 있다  
어떤 주문인지 delivery server에서 order server에 직접 요청한다면 coupling이 생긴다  
order server가 죽었을 때 delivery server에도 직접적으로 영향이 간다는 의미이다

2\. domain server의 endPoint를 노출하고 직접 호출하는 경우에는 security에 좋지 않다  
\-> gateway가 존재한다면 dataSource를 호출하는 domainServer의 endPoint를 숨길 수 있다

3\. logging은 각 domain에서 따로 관리한다고 가정하자  
issue가 발생할 경우 이를 확인하기 위해 4개의 domainServer의 logFile을 다 찾아야 할 수도 있다  
\-> gateway에서 log를 관리하면 gateway의 logFile만으로 어떤 issue가 있는지 알 수 있다

4\. routing policy를 적용할 때 global service의 region이 한국 1개, 미국 1개라고 가정하자  
미국에서 사용할 경우에는 접속자의 dns를 통해 위치를 확인하여 미국 server에 routing을 해야 한다  
그래야 성능이나 비용면에서 좋을 것이다  
하지만 gateway가 없다면 4개의 domainServer 전부 routing policy를 설정해야 할 것이다  
\-> gateway가 있다면 gateway server의 endPoint만으로 관리가 가능하다.

5\. cache가 각 domainServer별로 4개가 다 만들어지면 resource 낭비라고 생각한다  
\-> gateway를 사용하여 하나의 server에 chache를 사용하자  
부하 감소 및 성능 향상이 될 것이고 좀 더 일관적인 데이터를 반환할 것이다  
  

![](https://blog.kakaocdn.net/dn/AFteX/btsd0ufUGmN/xSHmnsQtKfKx5crtRVtENk/img.jpg)
