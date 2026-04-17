---
title: Jenkins를 이용한 Tomcat & Java JAR Docker CI/CD 구축 가이드
published: false
description: Docker와 Jenkins를 활용하여 Tomcat 기반 Java 애플리케이션의 CI/CD 파이프라인을 구축하는 완벽 가이드
tags: docker, cicd, jenkins, tomcat
cover_image: 
series:
---

# Jenkins를 이용한 Tomcat & Java JAR Docker CI/CD 구축 가이드

## 📑 목차

1. [환경 구성](#1-환경-구성)
2. [Docker Compose 테스트](#2-docker-compose-테스트)
3. [Harbor 저장소에 이미지 업로드](#3-harbor-저장소에-이미지-업로드)
4. [운영 서버에서 이미지 실행](#4-운영-서버에서-이미지-실행)
5. [Jenkins CI/CD 파이프라인 구성](#5-jenkins-cicd-파이프라인-구성)

---

## 1. 환경 구성

본 프로젝트에서 사용되는 기술 스택 버전은 다음과 같습니다:

- **Tomcat**: 11
- **JVM**: 17
- **Docker**: 25
- **Jenkins**: 2.427

---

## 2. Docker Compose 테스트

### 2.1 초기 설정

최초에는 프로젝트의 JAR 파일만 사용하여 Docker Compose로 테스트를 진행합니다.

### 2.2 검증 항목

다음 항목들이 정확하고 문제없는지 확인해야합니다

- Tomcat 버전
- Java 버전
- 애플리케이션의 모든 설정
- Profile 및 환경 변수

### 2.3 Docker Compose 실행

개발 환경에서는 빠른 재시작을 위해 다음 명령어를 사용합니다:

```bash
sudo docker-compose up -d --force-recreate
```

> **참고**: `build`와 `up`을 분리해도 되지만, 개발 단계에서는 `--force-recreate` 옵션으로 빠르게 진행합니다.

### 2.4 추가 설정

Tomcat에 필요한 설정 파일 및 구성을 `docker-compose.yml`에 추가합니다.

✅ 모든 테스트가 성공적으로 완료되면 다음 단계로 진행합니다.

---

## 3. Harbor 저장소에 이미지 업로드

### 3.1 Dockerfile 생성

위의 Docker Compose를 기반으로 Dockerfile을 작성하여 JAR 파일과 Tomcat을 함께 빌드합니다.

### 3.2 Harbor Registry 로그인

Harbor 저장소: https://docker-reg.coconev.jp/harbor/projects/10/repositories

Linux 서버에서 Harbor 저장소에 접근하려면 다음과 같이 로그인합니다:

```bash
echo "your_password" | docker login docker-reg.coconev.jp -u your_username --password-stdin
```

### 3.3 이미지 Push

로그인이 완료되면 빌드된 이미지를 Harbor 저장소에 업로드합니다:

```bash
docker push docker-reg.coconev.jp/rebirth/my-app:latest
```

---

## 4. 운영 서버에서 이미지 실행

### 4.1 이미지 Pull

운영 서버에서 Harbor 저장소로부터 이미지를 가져옵니다:

```bash
docker pull docker-reg.coconev.jp/rebirth/my-app:latest
```

### 4.2 컨테이너 실행

다운로드한 이미지를 실행합니다:

```bash
docker run docker-reg.coconev.jp/rebirth/my-app:latest
```

✅ 여기까지 문제없이 진행되었다면 Docker를 통한 실행이 성공적으로 검증된 것입니다.

### 4.3 프로젝트 파일 정리

이제 프로젝트에 다음 파일들을 저장합니다:
- Dockerfile
- Tomcat 관련 설정 파일

---

## 5. Jenkins CI/CD 파이프라인 구성

### 5.1 Jenkins 설치 및 설정

Jenkins를 설치하고, 두 개의 파이프라인을 생성합니다:
1. **Build Pipeline**: 애플리케이션 빌드 및 Docker 이미지 생성
2. **Deploy Pipeline**: 운영 서버에 배포

### 5.2 Build Pipeline

이 파이프라인은 소스 코드를 체크아웃하고, Gradle로 빌드하며, Docker 이미지를 생성하여 Harbor 저장소에 푸시합니다.

**주요 기능:**
- 선택적 워크스페이스 클린업 (RemoveAndBuild 모드)
- Git 소스 코드 체크아웃
- Gradle을 이용한 WAR 파일 빌드
- Docker 이미지 빌드 및 Harbor 저장소에 푸시

```groovy
pipeline {
    agent any

    parameters {
        choice(
            name: 'BUILD_MODE',
            choices: ['Default', 'RemoveAndBuild'],
            description: 'Select the build mode. (Default: normal build, RemoveAndBuild: delete all files and fresh checkout before build)'
        )
    }

    tools {
        jdk 'jdk-17.0.2'
    }

    stages {
        stage('Clean Workspace') {
            when {
                expression { env.BUILD_MODE == 'RemoveAndBuild' }
            }
            steps {
                echo "[INFO] Removing all files and folders in the workspace except Jenkins hidden files"
                deleteDir()
                echo "[INFO] Workspace deleted"
            }
        }
        
        stage('Checkout Source') {
            steps {
                echo "[INFO] Checking out source code from Git repository"
                git branch: "${BRANCH_NAME}", credentialsId: "hange_buildmachine", url: "${GIT_URL}"
                sh 'ls -al'
            }
        }
        
        stage('Copy Resources') {
            when {
                expression { env.BUILD_MODE == 'RemoveAndBuild' }
            }
            steps {
                echo "[INFO] Copy From resource-hange"
                withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-parameter-credentials']]) {
                    sh '''
                        chmod +x gradlew
                        ./gradlew copyResourceHange
                    '''
                }
            }
        }
        
        stage('Build & Unpack WAR') {
            steps {
                echo "[INFO] Starting build and WAR file unpack process"
                withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-parameter-credentials']]) {
                    sh '''
                        echo "[INFO] Starting Gradle build"
                        chmod +x gradlew
                        ./gradlew clean
                        ./gradlew bootWar -Pdeploy.phase=alpha

                        echo "[INFO] Build successful. Unpacking WAR file"
                        WAR_FILE=$(find ./build/libs -name "*.war" | head -1)
                        if [ -f "$WAR_FILE" ]; then
                          TARGET_DIR="./build/unpacked_war"
                          mkdir -p "$TARGET_DIR"
                          echo "[INFO] Unzipping $WAR_FILE to $TARGET_DIR"
                          unzip -o "$WAR_FILE" -d "$TARGET_DIR"
                          echo "[INFO] Unpack completed"
                        else
                          echo "[ERROR] WAR file not found!"
                          exit 1
                        fi
                    '''
                }
            }
        }
        
        stage('Docker Login (Harbor)') {
            steps {
                withCredentials([usernamePassword(
                    credentialsId: 'harbor_access_account',
                    usernameVariable: 'HARBOR_USER',
                    passwordVariable: 'HARBOR_PW'
                )]) {
                    sh '''
                        echo "$HARBOR_PW" | docker login "$REGISTRY" -u "$HARBOR_USER" --password-stdin
                    '''
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                sh '''
                    docker build -t ${IMAGE_REPO} .
                '''
            }
        }

        stage('Push Docker Image') {
            steps {
                sh '''
                    docker push ${IMAGE_REPO}
                '''
            }
        }
    }

    post {
        always {
            sh "docker logout ${REGISTRY} || true"
            sh "docker image prune -f || true"
        }
    }
}
```

---

### 5.3 Deploy Pipeline

이 파이프라인은 점프 호스트를 통해 운영 서버에 접속하여 Docker 이미지를 배포합니다.

**주요 기능:**
- Harbor 저장소에서 최신 이미지 Pull
- 기존 컨테이너 제거
- 새로운 컨테이너 실행 (디버그 포트 포함)

```groovy
pipeline {
    agent any
    
    stages {
        stage('Docker Pull Image') {
            steps {
                sh """
                    ssh -A ${SSH_COMMON_OPTS} -i \$SSH_KEY ${JUMP_HOST} \\
                        "ssh ${SSH_COMMON_OPTS} ${TARGET_HOST} \\
                            'echo \"${SUDO_PASSWORD}\" | sudo -S docker pull \"${DOCKER_IMAGE_REF}\"'"
                """
            }
        }
        
        stage('Remove Old Container') {
            steps {
                sh """
                    ssh -A ${SSH_COMMON_OPTS} -i \$SSH_KEY ${JUMP_HOST} \\
                        "ssh ${SSH_COMMON_OPTS} ${TARGET_HOST} \\
                            'echo \"${SUDO_PASSWORD}\" | sudo -S docker rm -f \"${PROJECT_NAME}\"'"
                """
            }
        }
        
        stage('Run New Container') {
            steps {
                sh """
                    ssh -A ${SSH_COMMON_OPTS} -i \$SSH_KEY ${JUMP_HOST} \\
                        "ssh ${SSH_COMMON_OPTS} ${TARGET_HOST} \\
                            'echo \"${SUDO_PASSWORD}\" | sudo -S docker run -d \\
                                --name \"${PROJECT_NAME}\" \\
                                -p \"${PORT}\":\"${PORT}\" \\
                                -p 9005:9005 \\
                                -p 5005:5005 \\
                                -e JAVA_TOOL_OPTIONS=\"-agentlib:jdwp=transport=dt_socket,address=*:5005,server=y,suspend=n\" \\
                                -e SPRING_PROFILES_ACTIVE=\"${SPRING_PROFILES_ACTIVE}\" \\
                                \"${DOCKER_IMAGE_REF}\" '"
                """
            }
        }
    }   
}
```

#### Deploy Pipeline 설명

**Stage 1: Docker Pull Image**
- 점프 호스트를 경유하여 운영 서버에 SSH 접속
- Harbor 저장소에서 최신 Docker 이미지를 Pull

**Stage 2: Remove Old Container**
- 기존에 실행 중인 컨테이너를 강제 종료 및 제거
- 다운타임을 최소화하기 위해 바로 다음 단계로 진행

**Stage 3: Run New Container**
- 새로운 컨테이너를 데몬 모드(-d)로 실행
- 포트 매핑:
  - `${PORT}`: 애플리케이션 포트
  - `9005`: JMX 포트
  - `5005`: 원격 디버깅 포트
- 환경 변수 설정:
  - `JAVA_TOOL_OPTIONS`: 원격 디버깅 활성화
  - `SPRING_PROFILES_ACTIVE`: Spring Profile 설정

---

## 📝 마무리

위 프로세스를 통해 Jenkins를 이용한 완전한 CI/CD 파이프라인을 구축할 수 있습니다.

### 전체 워크플로우 요약

1. **개발자가 코드를 Push**
2. **Jenkins Build Pipeline 실행**
   - 소스 코드 체크아웃
   - Gradle 빌드
   - Docker 이미지 생성
   - Harbor 저장소에 Push
3. **Jenkins Deploy Pipeline 실행**
   - Harbor에서 이미지 Pull
   - 운영 서버에 배포
   - 컨테이너 재시작

### 다음 단계

- [ ] 자동 테스트 단계 추가
- [ ] Slack/이메일 알림 설정
- [ ] 롤백 전략 구현
- [ ] Blue-Green 또는 Canary 배포 검토

---

**참고 링크:**
- [Jenkins 공식 문서](https://www.jenkins.io/doc/)
- [Docker 공식 문서](https://docs.docker.com/)
- [Harbor Registry](https://goharbor.io/)
