---
title: Jenkinsを利用したTomcat & Java JAR Docker CI/CD構築ガイド
published: false
description: DockerとJenkinsを活用してTomcatベースのJavaアプリケーションのCI/CDパイプラインを構築する完全ガイド
tags: docker, cicd, jenkins, tomcat
cover_image: 
series:
---

# Jenkinsを利用したTomcat & Java JAR Docker CI/CD構築ガイド

## 📑 目次

1. [環境構成](#1-環境構成)
2. [Docker Composeテスト](#2-docker-composeテスト)
3. [Harborレジストリへのイメージアップロード](#3-harborレジストリへのイメージアップロード)
4. [本番サーバーでのイメージ実行](#4-本番サーバーでのイメージ実行)
5. [Jenkins CI/CD Pipeline構成](#5-jenkins-cicd-pipeline構成)

---

## 1. 環境構成

本プロジェクトで使用される技術スタックのバージョンは以下の通りです：

- **Tomcat**: 11
- **JVM**: 17
- **Docker**: 25
- **Jenkins**: 2.427

---

## 2. Docker Composeテスト

### 2.1 初期設定

最初はプロジェクトのJARファイルのみを使用してDocker Composeでテストを行います。

### 2.2 検証項目

以下の項目が正確に問題なく動作しているか確認する必要があります：

- **Tomcatバージョン**: 正しいバージョンがインストールされているか確認
- **Javaバージョン**: JVM 17が正常に動作しているか確認
- **アプリケーション設定**: すべての設定ファイルが適切にロードされているか検証
- **Profile及び環境変数**: 開発/本番環境に合った設定が適用されているか確認

### 2.3 Docker Compose実行

開発環境では高速な再起動のために次のコマンドを使用します：

```bash
sudo docker-compose up -d --force-recreate
```

> **参考**: `build`と`up`を分離しても構いませんが、開発段階では`--force-recreate`オプションで素早く進めます。

### 2.4 追加設定

Tomcatに必要な設定ファイルと構成を`docker-compose.yml`に追加します。

✅ すべてのテストが正常に完了したら次のステップに進みます。

---

## 3. Harborレジストリへのイメージアップロード

### 3.1 Dockerfile作成

上記のDocker Composeを基にDockerfileを作成し、JARファイルとTomcatを一緒にビルドします。

### 3.2 Harbor Registry ログイン

**Harbor レジストリURL**: [https://docker-reg.coconev.jp/harbor/projects/10/repositories](https://docker-reg.coconev.jp/harbor/projects/10/repositories)

Linuxサーバーから Harborレジストリにアクセスするには、Dockerログインが必要です。セキュリティのため標準入力(stdin)を通じてパスワードを渡す方式を使用します：

```bash
echo "your_password" | docker login docker-reg.coconev.jp -u your_username --password-stdin
```

> **セキュリティTip**: 本番環境では環境変数やシークレット管理ツールを使用して認証情報を安全に管理してください。

### 3.3 イメージPush

ログインが完了したら、ビルドされたイメージをHarborレジストリにアップロードします：

```bash
docker push docker-reg.coconev.jp/rebirth/my-app:latest
```

---

## 4. 本番サーバーでのイメージ実行

### 4.1 イメージPull

本番サーバーからHarborレジストリよりイメージを取得します：

```bash
docker pull docker-reg.coconev.jp/rebirth/my-app:latest
```

### 4.2 Container実行

ダウンロードしたイメージでコンテナを実行します：

```bash
docker run docker-reg.coconev.jp/rebirth/my-app:latest
```

実際の本番環境ではポートマッピング、環境変数、volumeマウントなどの追加オプションが必要になる場合があります：

```bash
docker run -d \
  --name my-app \
  -p 8080:8080 \
  -e SPRING_PROFILES_ACTIVE=production \
  docker-reg.coconev.jp/rebirth/my-app:latest
```

✅ ここまで問題なく進行できたら、Dockerによるアプリケーション実行が正常に検証されたことになります。

### 4.3 プロジェクトファイルの整理

Docker実行が正常に検証されたら、次はプロジェクトに必要なファイルを整理します：

- **Dockerfile**: イメージビルドのための設定ファイル
- **Tomcat設定ファイル**: `server.xml`、`context.xml`などのTomcat構成ファイル
- **環境別設定ファイル**: 開発/ステージング/本番環境別の設定

これらのファイルをプロジェクトリポジトリにcommitしてバージョン管理すれば、その後Jenkinsで自動化されたCI/CDを構成できます。

---

## 5. Jenkins CI/CD Pipeline構成

### 5.1 Jenkinsインストール及び設定

Jenkinsをインストールして基本設定を完了した後、CI/CD workflowのためのpipelineを構成します。

### 5.2 Pipeline構造

効率的なデプロイのために、2つの独立したpipelineに分離することを推奨します：

**1. Build Pipeline**
- ソースコードcheckout
- Gradle/Maven build
- Dockerイメージ作成
- Harborレジストリへのイメージpush

**2. Deploy Pipeline**
- HarborからイメージPull
- 既存コンテナ停止及び削除
- 新しいコンテナ実行
- Health checkとデプロイ検証

### 5.3 次のステップ

Pipelineを構成した後は、以下の事項を追加で考慮できます：

- **自動化されたテスト**: 単体テスト、統合テスト追加
- **通知設定**: Slack、emailなどを通じたbuild/deploy結果の通知
- **Rollback戦略**: デプロイ失敗時に以前のバージョンに復旧するメカニズム
- **Monitoring連携**: Prometheus、Grafanaなどとの連携

---

## 📝 まとめ

このガイドでは、DockerとJenkinsを活用したTomcatベースのアプリケーションのCI/CD pipeline構築過程を扱いました。

### 全体Workflow

```
開発者コードPush 
    ↓
Docker Composeでローカルテスト
    ↓
Dockerfile作成及びイメージbuild
    ↓
Harbor Registryへイメージアップロード
    ↓
本番サーバーでイメージPull及び実行
    ↓
Jenkins CI/CD pipeline自動化
```

### 重要ポイント

- ✅ **段階的な検証**: 各段階で十分なテストを経て次の段階へ進む
- ✅ **セキュリティ考慮**: Harborログイン情報は安全に管理
- ✅ **自動化**: Jenkinsを通じて反復的な作業を自動化
- ✅ **モジュール化**: BuildとDeployを分離して柔軟性を確保

このようなプロセスを通じて、安定的で効率的なデプロイpipelineを構築できます。

---

**参考資料:**
- [Jenkins公式ドキュメント](https://www.jenkins.io/doc/)
- [Docker公式ドキュメント](https://docs.docker.com/)
- [Harborプロジェクト](https://goharbor.io/)
- [Apache Tomcatドキュメント](https://tomcat.apache.org/)

