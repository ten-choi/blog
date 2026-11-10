---
title: "[ Pattern ] database per service pattern"
labels: ["Architecture","design_pattern","jp","Pattern","MSA"]
published: true
date: 2023-12-07T17:45:22+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 200
tistoryUrl: "https://yeolceo.tistory.com/200"
tistoryCategory: "Architecture/design_pattern"
tistoryTags: ["jp","Pattern","MSA"]
tistoryPostedAt: "2023-12-07 17:45:22"
language: ja
bloggerPostId: "6902766073191225329"
---
## **database per service patternとは**

msaArchitectureで使われるパターンの一つで、一つのサービスに一つのdatabaseを使うパターンであります。

下図のようにorderServiceとcustomerServiceはそれぞれ異なるdbのtableを使用すると見えます。

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/200/img.webp)

## **このようにする理由**

monolithicProjectが巨大するほど理解, 変更, 拡張などが難しいです。

各サービスでdbをprivateに管理するためセキュリティが上がります。

dbを分けて使うのでその分負荷が減少し、頻繁に使用されるdbと頻繁に使用されないdbのスペックを異なるように設定することで、リソースの無駄を減らすことができます。

サービスのスキーマの所有権が明確になり管理しやすいです。

## **する前に確認**

サービスとdbのドメインがうまく区分されていない場合は、orderServiceでorderDbを照会しても希望する値がない場合があります。  

こうなると、該当サーバーですべきことを毎回他のサーバーに照会して使用するため、むしろトラフィックは増加し、効率性は低下します。

Reference

[https://microservices.io/post/microservices/patterns/data/2019/07/15/ftgo-database-per-service.html](https://microservices.io/post/microservices/patterns/data/2019/07/15/ftgo-database-per-service.html)
