sso 로그인을 한다
쿠키기준으로 볼수있다 로그인을한다 -> 게임에 접근한다 이건 sso ㅇ

# 🚀 Create a Simple Go Server

## Why

Golang: just wanna do
Fiber: fiber is fastest library on go web framworks just choce
mongo is useful and eazy because i dont have to create table to sql
docker is already major tool to deploy

## 🛠️ Step 1: Install Go

First, make sure Go is installed on your system.

- 👉 [Official Installation Guide](https://go.dev/doc/)
- 👉 [Beginner-Friendly Tutorial](https://go.dev/doc/tutorial/getting-started)

---

## 🗂️ Step 2: Set Up Your Project

1. **Create a new GitHub repository**  
   Go to GitHub and create a new repository (e.g., `go-test-server`).

2. **Clone the repository to your local machine**  
   For this guide, we’ll use the `C:\` drive:

   ```bash
   cd C:\
   git clone https://github.com/your-username/go-test-server.git
   cd go-test-server
   ```

3. **Create a `src` folder and add a simple `main.go` file**  
   Inside your `go-test-server` folder, create a `src` directory and then a `main.go` file inside it:

   ```go
   // src/main.go
   package main

   import "fmt"

   func main() {
       fmt.Println("Hello, World!")
   }
   ```

---

## ▶️ Run Your Go Program

To run the server, use the following command:

```bash
go run ./src/main.go
```

You should see:

```
Hello, World!
```

---

## 🌐 Create a Simple API with MongoDB

To create a simple API, you need a web framework and a database. We will use Fiber (a fast web framework for Go) and MongoDB (an easy-to-use database).

1. **Install the necessary libraries**  
   Use the following commands to install Fiber and MongoDB driver:

   ```bash
   go get -u github.com/gofiber/fiber/v2
   go get go.mongodb.org/mongo-driver/mongo
   ```

2. **Clean up unused dependencies**  
   If you have unused dependencies, you can remove them with:

   ```bash
   go mod tidy
   ```

3. **Initialize Swagger for API documentation**  
   To generate API documentation, install Swagger:

   ```bash
   go get -u github.com/swaggo/swag/cmd/swag
   ```

4. **Create environment files**  
   Create environment files for different environments (e.g., `env.local`, `env.dev`, `env.prod`).

---

## OpenApi and Env setting and Run Makefile

if you wanna documantation in goserver
go get -u github.com/swagger

get sagger setting

and run test naver

## 🚀 Deploy Your Server With Docker

1. **Create Docker configuration files**  
   Create `Dockerfile` and `docker-compose.yml` for containerization.

2. **Deploy to your server**  
   SSH into your server and run Docker and Docker Compose to start your server with MongoDB.

3. **Create GET and POST APIs**  
   Implement GET and POST APIs to verify that MongoDB is running correctly.

## ▶️ Run Your Go Program

To run the server, use the following command:

```bash
go run ./src/main.go
```

You should see:

```
Hello, World!
```

## Let create simple api with mongo

so you have to use webFramework and database

I'm going to use fiber and mongo
fiber is faster webFramework on golang and mongodb is eazy to change data

If you wanna use library in golang you can use under comand

go get -u github.com/fiber
go get go.mongodb.org/mongo-driver/mongo

if you don'y use some dependercy you can use this command
go mod tidy

this command is remove if you don't use depandency

swag init and use

create env file local, dev, prod
such liek env.local

and than you can create like file

## Let's deploy server

Dockerfile
docker-compose.yml

so you can go ssh in your server

run docker and docker-compose.yml

if run that server and use mongo

let's make get and post api because you have to chack your mongo is run

docker run -d --name my-redis -p 6379:6379 redis redis-server --requirepass "0814"

아래 거로 접근하려는데 안되면
redis-cli -h hange-rebirth-dev-0.coconefk -p 6379 -a 0814 ping
redis-cli -h localhost -p 6379 -a 0814 ping
실행중인 거에 접근해야한다

저기 redis에 접근 완료했다 이제 서버 만들고 로그인 토큰을 저기서 관리하면된다
기존의 쿠키가 있다면?

go get github.com/redis/go-redis/v9
이걸로 redis를 다운로드한다
