# Setting Up Kubernetes: A Practical Guide

do you know if alex sent the contract to the client?

mister miller 

In this tutorial, I'll walk you through my experience setting up a Kubernetes cluster using a mini PC as my server.

## Initial Setup Challenges

I'm using Linux 24, which doesn't have built-in support for the latest Kubernetes version. Before diving into Kubernetes installation, I made sure to configure the system time according to my timezone.

## Adding Kubernetes Repository

The standard `apt-get update` doesn't work immediately with Kubernetes. For version 1.30, you need to download Google Cloud's public signing key. I recommend getting this from the official Kubernetes site rather than using GPT-generated commands (which failed in my case).

To add the Kubernetes repository, you must use the `pkgs` source. Otherwise, it will fail because the files from Google Cloud's repository might not exist, resulting in errors:

```bash
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
```

Here's the official link where you can find installation instructions. Look for "v1-30" and change the numbers to access the correct version:
https://v1-30.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#installing-kubeadm-kubelet-and-kubectl

After adding the repository correctly, `apt-get update` should complete without issues.

## Installing Kubernetes Components

Install the core components with these commands:

```bash
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
