---
title: "Building a Docker CI/CD Pipeline for Tomcat & Java JARs with Jenkins"
labels: ["docker","cicd","jenkins","tomcat","Archive"]
published: true
date: 2025-03-17T13:52:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "3200306956621593052"
source: "archive"
archivePath: "_archive/dev/infra/cicd/docker-cicd-onjenkins.md"
---

# Building a Docker CI/CD Pipeline for Tomcat & Java JARs with Jenkins

## 📑 Table of Contents

1. [Environment](#1-environment)
2. [Testing with Docker Compose](#2-testing-with-docker-compose)
3. [Uploading the Image to Harbor](#3-uploading-the-image-to-harbor)
4. [Running the Image on the Production Server](#4-running-the-image-on-the-production-server)
5. [Setting Up the Jenkins CI/CD Pipelines](#5-setting-up-the-jenkins-cicd-pipelines)

---

## 1. Environment

This project uses the following versions:

- **Tomcat**: 11
- **JVM**: 17
- **Docker**: 25
- **Jenkins**: 2.427

---

## 2. Testing with Docker Compose

### 2.1 Initial Setup

To start, test with Docker Compose using only the project's JAR file.

### 2.2 What to Verify

Make sure each of the following is correct and working:

- Tomcat version
- Java version
- All application settings
- Profiles and environment variables

### 2.3 Running Docker Compose

In the development environment, use this command for quick restarts:

```bash
sudo docker-compose up -d --force-recreate
```

> **Note**: You can split `build` and `up`, but during development the `--force-recreate` option keeps things fast.

### 2.4 Additional Configuration

Add the configuration files and settings Tomcat needs to `docker-compose.yml`.

✅ Once every test passes, move on to the next step.

---

## 3. Uploading the Image to Harbor

### 3.1 Creating the Dockerfile

Based on the Docker Compose setup above, write a Dockerfile that builds the JAR file and Tomcat together.

### 3.2 Logging In to the Harbor Registry

Harbor registry: https://registry.example.com/harbor/projects/1/repositories

To access the Harbor registry from a Linux server, log in like this:

```bash
echo "your_password" | docker login registry.example.com -u your_username --password-stdin
```

### 3.3 Pushing the Image

Once you're logged in, push the built image to the Harbor registry:

```bash
docker push registry.example.com/myproject/my-app:latest
```

---

## 4. Running the Image on the Production Server

### 4.1 Pulling the Image

On the production server, pull the image from the Harbor registry:

```bash
docker pull registry.example.com/myproject/my-app:latest
```

### 4.2 Running the Container

Run the downloaded image:

```bash
docker run registry.example.com/myproject/my-app:latest
```

✅ If everything has gone smoothly up to this point, running via Docker has been successfully verified.

### 4.3 Organizing the Project Files

Now save the following files in the project:
- Dockerfile
- Tomcat configuration files

---

## 5. Setting Up the Jenkins CI/CD Pipelines

### 5.1 Installing and Configuring Jenkins

Install Jenkins and create two pipelines:
1. **Build Pipeline**: builds the application and creates the Docker image
2. **Deploy Pipeline**: deploys to the production server

### 5.2 Build Pipeline

This pipeline checks out the source code, builds it with Gradle, creates a Docker image, and pushes it to the Harbor registry.

**Key features:**
- Optional workspace cleanup (RemoveAndBuild mode)
- Git source checkout
- WAR file build with Gradle
- Docker image build and push to the Harbor registry

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
                git branch: "${BRANCH_NAME}", credentialsId: "git-credentials", url: "${GIT_URL}"
                sh 'ls -al'
            }
        }
        
        stage('Copy Resources') {
            when {
                expression { env.BUILD_MODE == 'RemoveAndBuild' }
            }
            steps {
                echo "[INFO] Copy From resource-repo"
                withCredentials([[$class: 'AmazonWebServicesCredentialsBinding', credentialsId: 'aws-parameter-credentials']]) {
                    sh '''
                        chmod +x gradlew
                        ./gradlew copyResources
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

This pipeline connects to the production server through a jump host and deploys the Docker image.

**Key features:**
- Pulls the latest image from the Harbor registry
- Removes the existing container
- Starts a new container (with debug ports)

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

#### How the Deploy Pipeline Works

**Stage 1: Docker Pull Image**
- SSH into the production server via the jump host
- Pull the latest Docker image from the Harbor registry

**Stage 2: Remove Old Container**
- Force-stop and remove the currently running container
- Move straight on to the next stage to minimize downtime

**Stage 3: Run New Container**
- Start the new container in detached mode (-d)
- Port mappings:
  - `${PORT}`: application port
  - `9005`: JMX port
  - `5005`: remote debugging port
- Environment variables:
  - `JAVA_TOOL_OPTIONS`: enables remote debugging
  - `SPRING_PROFILES_ACTIVE`: sets the Spring profile

---

## 📝 Wrapping Up

With the process above, you can build a complete CI/CD pipeline with Jenkins.

### Overall Workflow

1. **A developer pushes code**
2. **The Jenkins Build Pipeline runs**
   - Checks out the source code
   - Builds with Gradle
   - Creates the Docker image
   - Pushes it to the Harbor registry
3. **The Jenkins Deploy Pipeline runs**
   - Pulls the image from Harbor
   - Deploys it to the production server
   - Restarts the container

### Next Steps

- [ ] Add an automated test stage
- [ ] Set up Slack/email notifications
- [ ] Implement a rollback strategy
- [ ] Consider Blue-Green or Canary deployments

---

**References:**
- [Jenkins documentation](https://www.jenkins.io/doc/)
- [Docker documentation](https://docs.docker.com/)
- [Harbor Registry](https://goharbor.io/)
