---
title: "Kubernetes Installation and Setup Guide"
labels: ["kubernetes","docker","devops","k8s","monitoring","Archive"]
published: true
date: 2025-03-28T21:49:00+09:00
readerComments: "ALLOW"
language: en
bloggerPostId: "3269508961655564788"
source: "archive"
archivePath: "_archive/dev/infra/containers/쿠버네티스.md"
---

# Kubernetes Installation and Setup Guide

## Table of Contents

1. [Preparing the Environment](#1-preparing-the-environment)
2. [Installing Kubernetes](#2-installing-kubernetes)
3. [Initializing the Master Node](#3-initializing-the-master-node)
4. [Installing a Network Plugin (CNI)](#4-installing-a-network-plugin-cni)
5. [Installing the Kubernetes Dashboard](#5-installing-the-kubernetes-dashboard)
6. [Building a Monitoring Stack (Prometheus, Grafana, Loki)](#6-building-a-monitoring-stack-prometheus-grafana-loki)
7. [Troubleshooting and Tips](#7-troubleshooting-and-tips)

## 1. Preparing the Environment

This guide walks through building a Kubernetes cluster by installing Ubuntu Linux on a Mini PC.

### System Requirements

- OS: Ubuntu (※ Note: Ubuntu 24.04 is not currently an officially supported target for Kubernetes)
- CPU: at least 2 cores (4 cores recommended)
- Memory: at least 4GB
- Disk: at least 20GB

### Prerequisites

Set the system time zone correctly:

```bash
# Check the system time
timedatectl
# Set the time zone (e.g. Seoul)
sudo timedatectl set-timezone Asia/Seoul
```

## 2. Installing Kubernetes

### Adding the Kubernetes Repository

For Kubernetes 1.30, it's best to follow the method provided on the official site. Download the public signing key:

```bash
# Download the Kubernetes apt repository key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.30/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
```

Add the repository:

```bash
# Add the Kubernetes repository
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.30/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
```

> **Note**: To install a different version of Kubernetes, just change the version number in the official docs URL:  
> https://v1-30.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/

### Installing the Kubernetes Components

Update the package list and install the Kubernetes components:

```bash
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
```

Install containerd as the container runtime:

```bash
sudo apt-get install -y containerd
```

Initialize the containerd configuration:

```bash
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml
```

In the containerd config file, you need to change `SystemdCgroup = false` to `true`:

```bash
# Open the config file
sudo nano /etc/containerd/config.toml

# Find and edit the section below
# [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
# change to SystemdCgroup = true
```

Restart containerd and enable it to start automatically:

```bash
sudo systemctl restart containerd
sudo systemctl enable containerd
```

## 3. Initializing the Master Node

### Enabling IP Forwarding

First, you need to enable IP forwarding:

```bash
# Enable IP forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# Make the setting persist across reboots
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### Initializing with kubeadm

Initialize the master node, specifying the Pod network CIDR:

```bash
sudo kubeadm init --pod-network-cidr=192.168.0.0/16
```

> **Note**: `--pod-network-cidr=192.168.0.0/16` is the default for the Calico network plugin.

Once initialization finishes, set up the kubectl config file with the commands below:

```bash
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

## 4. Installing a Network Plugin (CNI)

Install the Calico network plugin. Version 3.27.0 is an LTS release that has been verified to work with Kubernetes 1.30:

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
```

After installing, check the node status:

```bash
kubectl get nodes
kubectl get pods -A
```

Once the node shows `Ready`, the installation succeeded.

## 5. Installing the Kubernetes Dashboard

### Deploying the Dashboard

Install the Kubernetes Dashboard:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml
```

### Creating an Admin Account and Permissions

Create an admin account and permissions for accessing the dashboard:

```bash
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kubernetes-dashboard
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-user-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kubernetes-dashboard
EOF
```

Generate a login token:

```bash
kubectl -n kubernetes-dashboard create token admin-user
```

### Configuring Dashboard Access

Change the dashboard service to NodePort so it can be reached from outside:

```bash
kubectl -n kubernetes-dashboard edit svc kubernetes-dashboard
# Find type: ClusterIP and change it to type: NodePort
```

Check the service's NodePort:

```bash
kubectl get svc -n kubernetes-dashboard
```

You can now reach the dashboard at `https://<server_IP>:<NodePort>`.

## 6. Building a Monitoring Stack (Prometheus, Grafana, Loki)

### Installing Helm

Install Helm, the Kubernetes package manager:

```bash
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
```

Verify the installation:

```bash
helm version
```

### Installing the Grafana Stack

Add the Grafana repository:

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
```

Install the monitoring stack, including Loki, Prometheus, and Grafana:

```bash
helm install loki-stack grafana/loki-stack \
  --namespace monitoring --create-namespace \
  --set grafana.enabled=true \
  --set prometheus.enabled=true \
  --set prometheus.server.persistentVolume.enabled=false \
  --set promtail.enabled=true \
  --set grafana.service.type=NodePort
```

> **Note**: `persistentVolume.enabled=false` is set for convenience in a development environment. In production, you should configure persistent storage.

Check the installation status:

```bash
kubectl get pods -n monitoring
kubectl get svc -n monitoring
```

### Accessing Grafana

Check the NodePort of the Grafana service:

```bash
kubectl get svc -n monitoring
```

Default login credentials:

- User: admin
- Password:

```bash
kubectl get secret --namespace monitoring loki-stack-grafana -o jsonpath="{.data.admin-password}" | base64 --decode
```

You can reach Grafana at `http://<server_IP>:<NodePort>`.

### Setting Up Dashboards

In Grafana, you can add dashboards with the following steps:

1. Home > Connections > Add new connection
2. Add the Loki data source
3. Import useful dashboards such as "Node Exporter Full" from the Grafana.com dashboard browser

## 7. Troubleshooting and Tips

### Allowing Pods to Be Scheduled on the Master Node

By default, the master node has a taint that keeps Pods from being scheduled on it. In a development environment, you can remove it:

```bash
# Check the taint
kubectl describe node <node-name> | grep Taint

# Remove the taint
kubectl taint nodes <node-name> node-role.kubernetes.io/control-plane-
```

### Resetting the Installation (If Needed)

If something goes wrong and you need to reinstall from scratch:

```bash
sudo kubeadm reset -f
sudo rm -rf ~/.kube /etc/kubernetes /var/lib/etcd /etc/cni/net.d
sudo systemctl restart containerd
sudo systemctl restart kubelet
```

### Configuring External Access

You can reach services from outside through an SSH tunnel:

```bash
# Forward local port 8443 to port 8443 on the remote server
ssh -L 8443:localhost:8443 username@server_ip

# Forward local port 3000 to port 3000 on the remote server (Grafana)
ssh -L 3000:localhost:3000 username@server_ip
```

In a development environment, though, switching the service type to NodePort may be more convenient.

---

This document is a basic guide to building a Kubernetes cluster on a Mini PC and setting up a monitoring environment. A real production environment needs additional considerations such as security, high availability, and backups.
