---
title: 쿠버네티스(Kubernetes) 설치 및 구성 가이드
published: false
description: Mini PC에서 쿠버네티스 클러스터 구축 및 모니터링 환경 설정하기
tags: kubernetes, docker, devops, k8s, monitoring
cover_image: https://example.com/your-cover-image.jpg
series:
---

# 쿠버네티스(Kubernetes) 설치 및 구성 가이드

## 목차

1. [환경 준비](#1-환경-준비)
2. [쿠버네티스 설치](#2-쿠버네티스-설치)
3. [마스터 노드 초기화](#3-마스터-노드-초기화)
4. [네트워크 플러그인(CNI) 설치](#4-네트워크-플러그인cni-설치)
5. [쿠버네티스 대시보드 설치](#5-쿠버네티스-대시보드-설치)
6. [모니터링 스택 구축 (Prometheus, Grafana, Loki)](#6-모니터링-스택-구축-prometheus-grafana-loki)
7. [트러블슈팅 및 팁](#7-트러블슈팅-및-팁)

## 1. 환경 준비

본 가이드는 Mini PC에 Ubuntu Linux를 설치하여 쿠버네티스 클러스터를 구축하는 과정을 다룹니다.

### 시스템 요구사항

- 운영체제: Ubuntu (※ 주의: Ubuntu 24.04는 현재 쿠버네티스 공식 지원 대상이 아닙니다)
- CPU: 최소 2코어 이상 (4코어 권장)
- 메모리: 최소 4GB 이상
- 디스크: 최소 20GB 이상

### 사전 설정

시스템 시간대를 맞게 설정합니다:

```bash
# 시스템 시간 확인
timedatectl
# 시간대 설정 (예: 서울)
sudo timedatectl set-timezone Asia/Seoul
```

## 2. 쿠버네티스 설치

### 쿠버네티스 리포지토리 추가

쿠버네티스 1.30 버전의 경우 공식 사이트에서 제공하는 방법을 사용하는 것이 좋습니다. 공개 서명 키를 다운로드합니다:

```bash
# 쿠버네티스 apt 저장소 키 다운로드
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
```

저장소를 추가합니다:

```bash
# 쿠버네티스 저장소 추가
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
```

> **참고**: 다른 버전의 쿠버네티스를 설치하려면 공식 문서 URL의 버전 번호를 변경하면 됩니다:  
> https://v1-30.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/

### 쿠버네티스 컴포넌트 설치

패키지 목록을 업데이트하고 쿠버네티스 컴포넌트를 설치합니다:

```bash
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
```

컨테이너 런타임으로 containerd를 설치합니다:

```bash
sudo apt-get install -y containerd
```

containerd 설정을 초기화합니다:

```bash
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml
```

containerd 설정 파일에서 `SystemdCgroup = false`를 `true`로 변경해야 합니다:

```bash
# 설정 파일 열기
sudo nano /etc/containerd/config.toml

# 아래 부분을 찾아 수정
# [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
# SystemdCgroup = true로 변경
```

containerd를 재시작하고 자동 시작되도록 설정합니다:

```bash
sudo systemctl restart containerd
sudo systemctl enable containerd
```

## 3. 마스터 노드 초기화

### IP 포워딩 활성화

먼저 IP 포워딩을 활성화해야 합니다:

```bash
# IP 포워딩 활성화
sudo sysctl -w net.ipv4.ip_forward=1

# 재부팅 후에도 설정이 유지되도록 설정
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### kubeadm을 사용한 초기화

Pod 네트워크 CIDR을 지정하여 마스터 노드를 초기화합니다:

```bash
sudo kubeadm init --pod-network-cidr=192.168.0.0/16
```

> **참고**: `--pod-network-cidr=192.168.0.0/16`는 Calico 네트워크 플러그인의 기본 설정입니다.

초기화가 완료되면 아래 명령으로 kubectl 설정 파일을 구성합니다:

```bash
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

## 4. 네트워크 플러그인(CNI) 설치

Calico 네트워크 플러그인을 설치합니다. 버전 3.27.0은 LTS 버전으로 쿠버네티스 1.30과 호환성이 검증되었습니다:

```bash
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
```

설치 후 노드 상태를 확인합니다:

```bash
kubectl get nodes
kubectl get pods -A
```

노드가 `Ready` 상태가 되면 정상적으로 설치된 것입니다.

## 5. 쿠버네티스 대시보드 설치

### 대시보드 배포

쿠버네티스 대시보드를 설치합니다:

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml
```

### 관리자 계정 및 권한 생성

대시보드 접근을 위한 관리자 계정과 권한을 생성합니다:

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

로그인용 토큰을 생성합니다:

```bash
kubectl -n kubernetes-dashboard create token admin-user
```

### 대시보드 접근 설정

대시보드 서비스를 NodePort로 변경하여 외부에서 접근할 수 있게 합니다:

```bash
kubectl -n kubernetes-dashboard edit svc kubernetes-dashboard
# type: ClusterIP를 찾아 type: NodePort로 변경
```

서비스의 NodePort를 확인합니다:

```bash
kubectl get svc -n kubernetes-dashboard
```

이제 `https://<서버_IP>:<NodePort>`로 대시보드에 접근할 수 있습니다.

## 6. 모니터링 스택 구축 (Prometheus, Grafana, Loki)

### Helm 설치

쿠버네티스 패키지 관리자인 Helm을 설치합니다:

```bash
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
```

설치 확인:

```bash
helm version
```

### Grafana 스택 설치

Grafana 리포지토리를 추가합니다:

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
```

Loki, Prometheus, Grafana를 포함한 모니터링 스택을 설치합니다:

```bash
helm install loki-stack grafana/loki-stack \
  --namespace monitoring --create-namespace \
  --set grafana.enabled=true \
  --set prometheus.enabled=true \
  --set prometheus.server.persistentVolume.enabled=false \
  --set promtail.enabled=true \
  --set grafana.service.type=NodePort
```

> **참고**: `persistentVolume.enabled=false`는 개발 환경에서의 편의를 위해 설정했습니다. 프로덕션 환경에서는 영구 저장소를 구성하는 것이 좋습니다.

설치 상태를 확인합니다:

```bash
kubectl get pods -n monitoring
kubectl get svc -n monitoring
```

### Grafana 접근

Grafana 서비스의 NodePort를 확인합니다:

```bash
kubectl get svc -n monitoring
```

기본 로그인 정보:

- 사용자: admin
- 비밀번호:

```bash
kubectl get secret --namespace monitoring loki-stack-grafana -o jsonpath="{.data.admin-password}" | base64 --decode
```

`http://<서버_IP>:<NodePort>`로 Grafana에 접근할 수 있습니다.

### 대시보드 설정

Grafana에서 다음 단계로 대시보드를 추가할 수 있습니다:

1. Home > Connections > Add new connection
2. Loki 데이터 소스 추가
3. Grafana.com 대시보드 탐색에서 "Node Exporter Full" 등의 유용한 대시보드 가져오기

## 7. 트러블슈팅 및 팁

### 마스터 노드에 Pod 스케줄링 허용

기본적으로 마스터 노드에는 Pod가 스케줄링되지 않도록 taint가 설정되어 있습니다. 개발 환경에서는 이를 제거할 수 있습니다:

```bash
# taint 확인
kubectl describe node <노드명> | grep Taint

# taint 제거
kubectl taint nodes <노드명> node-role.kubernetes.io/control-plane-
```

### 설치 초기화 (필요 시)

문제가 발생하여 처음부터 다시 설치해야 하는 경우:

```bash
sudo kubeadm reset -f
sudo rm -rf ~/.kube /etc/kubernetes /var/lib/etcd /etc/cni/net.d
sudo systemctl restart containerd
sudo systemctl restart kubelet
```

### 외부 접근 설정

SSH 터널을 통해 외부에서 서비스에 접근할 수 있습니다:

```bash
# 로컬 8443 포트를 원격 서버의 8443 포트로 연결
ssh -L 8443:localhost:8443 username@server_ip

# 로컬 3000 포트를 원격 서버의 3000 포트로 연결 (Grafana)
ssh -L 3000:localhost:3000 username@server_ip
```

하지만 개발 환경에서는 서비스 유형을 NodePort로 변경하는 것이 더 편리할 수 있습니다.

---

이 문서는 Mini PC에서 쿠버네티스 클러스터를 구축하고 모니터링 환경을 설정하는 기본 가이드입니다. 실제 프로덕션 환경에서는 보안, 고가용성, 백업 등 추가적인 고려 사항이 필요합니다.
