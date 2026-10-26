---
title: "[ Spring ] java springを簡単に始めましょう"
labels: ["Java","Kotlin","spring","jp","springboot"]
published: false
date: 2023-12-07T20:22:46+09:00
readerComments: "ALLOW"
source: "tistory"
tistoryId: 208
tistoryUrl: "https://yeolceo.tistory.com/208"
tistoryCategory: "Java, Kotlin/spring"
tistoryTags: ["Java","Spring","jp","springboot"]
tistoryPostedAt: "2023-12-07 20:22:46"
language: ja
bloggerPostId: "6696462684905575932"
---
## **What is the Spring**

Javaを基盤とするウェブフレームワークで、Javaで様々なアプリケーションを開発するための効率的な枠組みといえます。

 JSP、MyBatis、JPAなどの技術がJavaを通じてプロジェクトに適用され、Springはこれらの技術をより効率的に活用できるように作られました。

プロジェクトを進めていると、分業しても重複するコードが発生する場合が多いです。 Springは、これらの重複コードを最小限に抑え、ビジネスロジックを簡潔に実装するのに役立ちます。

Springを使用すると、他の開発者のコードを参考にして簡単に適用できます。 これはオープンソースを効果的に活用できる構造を備えているという意味です。

要するに、SpringはJava技術をより手軽に活用できるように支援するオープンソースフレームワークです。

## How to start project

springBootとはspringをより使いやすくするためのinitializerであります。

mavenとgradleというビルド管理ツールがあります。

簡単に説明しますと、速度や安定性のためにgradleに移る傾向があります。

該当経路 [https://start.spring.io/](https://start.spring.io/) でspringBoot ファイルをダウンロードしましょう。

1.  project: gradleで進めます。
2.  language: javaを選びます。
3.  springBoot: snapShotとか付いてないバージョンが正式バージョンで、その中で最新を使用します。
4.  group: 会社名や当該プロジェクトのドメイン名前を書きます。
5.  artifact: 開発するアプリケーションの名前を書きます。
6.  name, description: 名前と説明は自動的に満たされます。
7.  pakageName: groupとartifactが組み合わさって出てくるパッケージ名であります。パッケージ名として使用されるため、私はハイフンを除去して使用します。
8.  Jar: プロジェクト内部に内蔵tomcatを使用します。それで私はJarで進行します。  
    War: プロジェクト外部にtomcatを使用します。
9.  dependences: springBootを通じてあらかじめ使用したいライブラリを追加します。

下のgenerateボタンを押しってこれまでの設定をダウンロードしてくれます。

## **Create project and run server**

自分のgithubアカウントを通じてrepositoryを作ってくれます。そして、パソコンに望むルートにクローンをダウンロードします。  

クローンされたルートにspringBootを圧縮解除します。  

intellijを使用し、build.gradleというファイルを選択しopen as projectボタンを押します。  

intellijで自動的にdependenciesなどのダウンロードを行います。  

src→main→java→applicationファイルのクラスを実行すると、javaサーバーが実行されます。  

localhost:8080に接続して確認してみましょう。
