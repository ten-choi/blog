---
title: "[ Ide ] intellijで整列する方法"
labels: ["ETC","jp","IntelliJ","ide","reformat"]
published: false
date: 2023-11-26T13:17:00+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 198
tistoryUrl: "https://yeolceo.tistory.com/198"
tistoryCategory: "ETC"
tistoryTags: ["jp","IntelliJ","ide","reformat"]
tistoryPostedAt: "2023-11-26 13:17:00"
language: ja
bloggerPostId: "4025926090051763162"
---
## **コード整列に対して**

コードが読みやすいと、チームで働くときにはるかに役立ちます。

この時、整列がよくできている部分も非常に重要です。

windowではコードを整列するショートカットキーがctrl+art+Lであります。 

コーディングのたびにこれを押すのは余計なことだと思います。

intellijも当たり前にreformat機能があります。

## **設定方法**

1\. SaveActions plugin 使用

ctrl+sを押すとき自動的に整列してくれる動作をしてくれるプラグインが存在します。

file →setting →plugins → ここで探す

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/198/img.webp)

2\. 最新のintellijを使う時

ctr+sを押す時に整列をしてくれるオプションが存在します。

それでプラグインを設置する必要がないです。

file →setting →Tools →Actions on Save → check Reformat code

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/198/img_1.webp)

intellijの基本機能を使用することが今後も継続的に管理されそうなので、私は二つ目を使用しています。
