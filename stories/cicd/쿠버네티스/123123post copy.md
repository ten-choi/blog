# Setting Up Kubernetes: A Practical Guide

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
```

This installs the components and pins their versions to prevent automatic updates.

## Setting Up Container Runtime

Next, install containerd:

```bash
sudo apt-get install -y containerd
```

Initialize the configuration with these commands:

```bash
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml
sudo systemctl restart containerd
sudo systemctl enable containerd
```
a
This creates the default configuration for containerd, restarts the service, and enables it to start automatically on boot.
a
## Initializing the Master Node (kubeadm init)

To initialize the master node, use the following command:

```bash
sudo kubeadm init --pod-network-cidr=192.168.0.0/16
```

The `--pod-network-cidr` flag specifies the virtual IP range for Pods, which depends on the CNI (e.g., Calico, Flannel) you plan to install later. The range `192.168.0.0/16` is commonly used with Calico.

### Post-Initialization Steps

After initialization, you'll see output similar to this:

- `kubeadm join ...` → Command to connect worker nodes to the cluster
- `/etc/kubernetes/admin.conf` → API server access credentials

If you encounter an IP forwarding issue, enable it with:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

To make this setting persistent across reboots:

```bash
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

Re-run the kubeadm initialization command if needed:

```bash
sudo kubeadm init --pod-network-cidr=192.168.0.0/16
```

### Configuring kubectl

Create a hidden directory and copy the admin configuration file:

```bash
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

## Installing Calico CNI

Calico is a CNI plugin that controls Pod communication and enforces network policies. Version 3.27 is recommended for Kubernetes 1.30:

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
```

If you encounter issues with `SystemdCgroup = false`, change it to `true` in the containerd configuration:

```toml
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
  SystemdCgroup = true
```

Restart containerd:

```bash
sudo systemctl restart containerd
```

## Resetting and Reinitializing

If you need to reset and start over:

```bash
sudo kubeadm reset -f
sudo rm -rf ~/.kube /etc/kubernetes /var/lib/etcd /etc/cni/net.d
sudo systemctl restart containerd
sudo systemctl restart kubelet
```

Reinitialize the master node:

```bash
sudo kubeadm init --pod-network-cidr=192.168.0.0/16
```

Reconfigure kubectl:

```bash
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

Reinstall Calico CNI:

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
```

Verify the nodes and pods:

```bash
kubectl get nodes
kubectl get pods -A
```

## Installing Kubernetes Dashboard

Install the Kubernetes Dashboard:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml
```

### Creating an Admin ServiceAccount

Create an admin ServiceAccount and ClusterRoleBinding:

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

### Retrieving the Token

Get the token for Dashboard login:

```bash
kubectl -n kubernetes-dashboard create token admin-user
```

Forward the port to access the Dashboard:

```bash
kubectl port-forward -n kubernetes-dashboard service/kubernetes-dashboard 8443:443
```

### Handling Taints

If you encounter issues with pods in a pending state, it's likely due to taints on the master node. Remove the taint:

```bash
kubectl taint nodes ubuntu node-role.kubernetes.io/control-plane-
```

Verify the pods are running:

```bash
kubectl get pods -n kubernetes-dashboard -w
```

Forward the port again to access the Dashboard:

```bash
kubectl port-forward -n kubernetes-dashboard service/kubernetes-dashboard 8443:443
```

## Accessing the Dashboard Externally

To access the Dashboard from another computer, use SSH port forwarding:

```bash
ssh -L 8443:localhost:8443 user@your-server-ip
```

Access the Dashboard at `https://localhost:8443` using the admin-user token.

## Monitoring with Prometheus, Grafana, and Loki

First, install Helm, the Kubernetes package manager:

```bash
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
```

Verify the installation:

```bash
helm version
```

Add the Grafana Helm repository and update:

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
```

Install the Loki stack with Grafana and Prometheus:

```bash
helm install loki-stack grafana/loki-stack \
  --namespace monitoring --create-namespace \
  --set grafana.enabled=true \
  --set prometheus.enabled=true \
  --set promtail.enabled=true
```

Verify the pods in the monitoring namespace:

```bash
kubectl get pods -n monitoring
```

Forward the port to access Grafana:

```bash
kubectl port-forward -n monitoring service/loki-stack-grafana 3000:80
```

Use SSH port forwarding to access Grafana from another computer:

```bash
ssh -L 3000:localhost:3000 user@your-server-ip
```

To make Grafana accessible externally, change the service type to NodePort:

```bash
helm upgrade loki-stack grafana/loki-stack -n monitoring --set grafana.service.type=NodePort
```

Verify the service:

```bash
kubectl get svc -n monitoring
```

Access Grafana using the external IP and NodePort. The default credentials are:

- Username: admin
- Password: (retrieve with the following command)

```bash
kubectl get secret --namespace monitoring loki-stack-grafana -o jsonpath="{.data.admin-password}" | base64 --decode
```

## Importing Dashboards

Import dashboards from Grafana's website. For example, import the "Node Exporter Full" dashboard.

If you encounter issues with Prometheus, ensure it has access to persistent storage or disable it for testing:

```bash
helm upgrade loki-stack grafana/loki-stack \
  -n monitoring \
  --set grafana.enabled=true \
  --set grafana.service.type=NodePort \
  --set prometheus.enabled=true \
  --set prometheus.server.persistentVolume.enabled=false \
  --set promtail.enabled=true
```

Verify Prometheus is running:

```bash
kubectl get pods -n monitoring | grep prometheus
```

## Updating Kubernetes Dashboard to NodePort

To avoid using SSH port forwarding for the Kubernetes Dashboard, change its service type to NodePort:

```bash
kubectl -n kubernetes-dashboard edit svc kubernetes-dashboard
```

Change `type: ClusterIP` to `type: NodePort` and save. Verify the service:

```bash
kubectl get svc -n kubernetes-dashboard
```

Reissue the admin-user token if needed.

## Conclusion

This guide covers the essential steps to set up a Kubernetes cluster, install necessary components, and configure monitoring tools. With these instructions, you should be able to get your Kubernetes environment up and running smoothly.
