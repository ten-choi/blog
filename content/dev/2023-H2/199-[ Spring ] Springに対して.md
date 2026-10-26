---
title: "[ Spring ] Springに対して"
labels: ["Java","Kotlin","spring","jp","springboot"]
published: false
date: 2023-12-01T10:37:14+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 199
tistoryUrl: "https://yeolceo.tistory.com/199"
tistoryCategory: "Java, Kotlin/spring"
tistoryTags: ["Java","Spring","jp","springboot"]
tistoryPostedAt: "2023-12-01 10:37:14"
language: ja
bloggerPostId: "9112575663414822903"
---
## **Springとは**

javaで開発する時に便利なオープンソース軽量級アプリケーションフレームワークです。

オープンソースなので、複数の人が使用して検証過程を経ており、コードを修正して使用しても問題ありません。

軽量級の意味は、以前の技術に比べてspringを使えば、開発者が作成するコードが相対的に減るといいます。

アプリケーションを作成するために特化した目的のフレームワークであるため、開発時に多くの骨組みを提供し、開発が容易です。上記のような意味を持っています。

## **Springの特徴**

特徴はpojoを目指すというところです。

pojoとは、Plain Old Java Object、つまり純粋なjavaだけを通じて生成したオブジェクトのことです。

![](https://cdn.jsdelivr.net/gh/ten-choi/blog-images@main/dev/tistory/199/img.webp)

簡単に説明すると、javaがすべて管理する開発を目指すということですが、これは外部ライブラリやモジュールを使用する場合、それが変更された時に簡単に対応できるコードを目指せという意味です。

そうなれば、拡張と変化に柔軟に対処できるでしょう。

それを助ける技術のspringにはIoC/DI、AOP、PSAというものがあり、この部分は他の記事で作成する予定です。

## **springBootを利用して開発**

[https://start.spring.io/](https://start.spring.io/)

springBootはspringでアプリケーションを作る時に必要な設定を簡単に処理してくれる別途のフレームワークです。

既存の困難な初期設定に費やすべきだった時間と労力を節約し、ビジネスロジックの開発に集中できます。

結果的にspringを使って開発を始めたい時、java、Ide(intellij)、springbootがある場合、開発するための基本的な環境を作ることができます。
