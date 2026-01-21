---
title: CI/CD with Jenkins, Docker & Git - A Simple Guide for Junior Developers
published: false
description: Learn how to set up a complete CI/CD pipeline using Jenkins, Docker, and GitHub
tags: jenkins, docker, cicd, devops
cover_image: https://img.notionusercontent.com/s3/prod-files-secure%2F6ab3efe6-44b5-4e5c-9d86-56543fb7f59d%2F452901b3-0f1b-40ca-92c6-a79b6c640686%2FChatGPT_Image_Jan_21_2026_11_36_45_AM.png/size/w=1420?exp=1769049462&sig=C7NJxcraISDtsjWxDx7gvToYSdgCkh_mTCWvPj46FZ4&id=2ef930ff-582f-80b6-b7ff-cc49ec3a3764&table=block
series: cicd 
---

# Easy CI/CD Setup with Jenkins, Docker & Git

## What You'll Need

Before we start, make sure you have:
- Basic **GitHub** knowledge
- A **Linux server** (or VM)
- Some **Docker** experience

## Overview

Hey! If you're a **junior developer** looking to learn CI/CD, you're in the right place! This guide is specifically written for beginners who want to understand how to automate their deployment process.

Today I'm going to walk you through setting up CI/CD with Docker and Jenkins from scratch. Don't worry if this sounds intimidating - it's actually pretty straightforward! With modern tools (and a bit of AI help), anyone can build a solid pipeline without too much hassle.

So, without further ado, let's dive in!

---

## Step 1: GitHub Setup

First things first - let's get your GitHub ready:

1. **Create a repository** on GitHub for your project
2. Go to **Settings** → **Developer settings** → **Personal access tokens**
3. **Generate a new token** (make sure to save it somewhere safe - you'll need it later!)

---

## Step 2: Local Development

Now let's work on your local machine:

1. **Write your code** - use whatever language you prefer (Java, Python, Go, Node.js - anything works!)
2. **Create a Dockerfile** for building your app
3. **Test the Docker build** locally to make sure everything works:
   ```bash
   docker build -t your-app:latest .
   ```
   If it builds successfully, you're good to go!

---

## Step 3: Server Setup

Time to prep your deployment server:

1. **Update your package manager**:
   ```bash
   sudo apt update -y
   ```

2. **Install Docker and docker-compose**:
   ```bash
   sudo apt install docker.io docker-compose-plugin -y
   ```

3. **Create a docker-compose file for Jenkins**:
   
   Here's a simple setup that works:
   ```yaml
   services:
     jenkins:
       image: jenkins/jenkins:lts
       user: root  # avoid permission errors
       ports:
         - "8080:8080"
       volumes:
         - ./jenkins_home:/var/jenkins_home
         - /var/run/docker.sock:/var/run/docker.sock
   ```
   
   **Important tips:**
   - The volumes setup ensures your Jenkins config persists across restarts
   - Mounting the Docker socket lets Jenkins control Docker on the host
   - Pro tip: Store this compose file in a GitHub repo for version control! 
---

## Step 4: Jenkins Configuration 

Alright, now for the fun part - setting up Jenkins:

1. **Add GitHub credentials**:
   - Use that personal access token you created earlier
   - Store it securely in Jenkins credentials manager

2. **Create a Pipeline** with these stages:
   
   Your pipeline should look something like this (don't worry, you can use AI to help write the Jenkinsfile!):
   
   1. **Checkout** - Pull your code from GitHub
   2. **Build** - Build your Docker image
   3. **Login** - Authenticate with Docker Hub
   4. **Push** - Push your image to Docker Hub
   5. **SSH to server** - Connect to your deployment server
   6. **Deploy** - Run your updated container

3. **Set up automatic triggering:**
   
   You have two options here:
   
   **Option A: Webhooks (if you have a public IP)**
   - Simply create a webhook in your GitHub repository settings
   - Jenkins will automatically trigger the build as soon as you push code
   - This is the cleanest approach!
   
   **Option B: Poll SCM (if you don't have a public IP)**
   - Set up a Jenkins cron schedule to check for updates (e.g., every 2 minutes)
   - Make sure you have a Jenkinsfile in your repository
   - Not as instant as webhooks, but gets the job done






## Bonus: Easy Log Viewing with Dozzle

Want to see your container logs easily? Let me introduce you to **Dozzle** - it's a game changer!

1. Go to the [Dozzle homepage](https://dozzle.dev/)
2. Copy the docker installation command
3. Run it on your Linux server:
   ```bash
   docker run -d --name dozzle -v /var/run/docker.sock:/var/run/docker.sock -p 9999:9999 amir20/dozzle:latest
   ```

That's it! Now you can view all your container logs in a nice web interface at `http://your-server:9999` 🎉

No more SSH-ing into your server just to check logs!

---

## Wrapping Up

Congrats! You now have a fully working CI/CD pipeline. Every time you push code to GitHub, Jenkins will automatically build and deploy your app. Pretty cool, right?

The best part? Once it's set up, you can pretty much forget about it and focus on writing code. Your deployments will just... happen.

Happy coding! 🚀






