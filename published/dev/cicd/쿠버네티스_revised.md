---
title: 쿠버네티스(Kubernetes) 설치 및 구성 가이드
published: false
description: Mini PC에서 쿠버네티스 클러스터 구축 및 모니터링 환경 설정하기
tags: kubernetes, docker, devops, k8s, monitoring
cover_image: https://example.com/your-cover-image.jpg
series: Kubernetes 실습 시리즈
---

# 쿠버네티스(Kubernetes) 설치 및 구성 가이드

안녕하세요! 👋 집에 있는 Mini PC로 쿠버네티스 클러스터를 직접 구축해보고 싶으신가요? 이 글에서는 Ubuntu 기반으로 쿠버네티스를 설치하고, 대시보드와 모니터링 환경까지 세팅하는 과정을 함께 따라해볼 거예요.

## 목차

1. [환경 준비](#1-환경-준비)
2. [쿠버네티스 설치](#2-쿠버네티스-설치)
3. [마스터 노드 초기화](#3-마스터-노드-초기화)
4. [네트워크 플러그인(CNI) 설치](#4-네트워크-플러그인cni-설치)
5. [쿠버네티스 대시보드 설치](#5-쿠버네티스-대시보드-설치)
6. [모니터링 스택 구축 (Prometheus, Grafana, Loki)](#6-모니터링-스택-구축-prometheus-grafana-loki)
7. [트러블슈팅 및 팁](#7-트러블슈팅-및-팁)

## 1. 환경 준비

먼저 시작하기 전에 필요한 것들을 체크해볼게요!

### 시스템 요구사항

- 운영체제: Ubuntu 22.04 LTS 권장 (💡 팁: Ubuntu 24.04는 아직 쿠버네티스 공식 지원이 안 되니 22.04나 20.04를 쓰세요)
- CPU: 최소 2코어 이상 (4코어면 더 좋겠죠!)
- 메모리: 최소 2GB 이상 (4GB 권장)
- 디스크: 최소 20GB 이상

### 사전 설정

시작하기 전에 몇 가지 필수 설정을 해야 해요!

**1. 스왑 메모리 비활성화**

쿠버네티스는 성능상의 이유로 swap을 꺼야 돌아가요. 이거 안 하면 kubeadm이 에러를 뱉습니다! 😅

```bash
# swap 즉시 비활성화
sudo swapoff -a

# 재부팅 후에도 swap이 꺼지도록 설정
sudo sed -i '/ swap / s/^/#/' /etc/fstab
```

**2. 시스템 시간대 설정**

시간대도 맞춰놓을게요. 이게 안 맞으면 나중에 인증서 문제로 골치 아플 수 있거든요.

```bash
# 시스템 시간 확인
timedatectl
# 시간대 설정 (예: 서울)
sudo timedatectl set-timezone Asia/Seoul
```

## 2. 쿠버네티스 설치

### 쿠버네티스 리포지토리 추가

이제 본격적으로 쿠버네티스를 설치해볼게요! 먼저 공식 리포지토리를 추가해야 하는데요, 공개 서명 키부터 받아옵시다:

```bash
# 쿠버네티스 apt 저장소 키 다운로드
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://pkgs.k8s.io/core:/stable:/v1.28/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg
```

그 다음 저장소를 추가해줍니다:

```bash
# 쿠버네티스 저장소 추가
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list
```

> 💡 **참고로**: 다른 버전을 쓰고 싶으시다면 URL의 버전 번호만 바꿔주면 돼요!  
> https://v1-30.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/

### 쿠버네티스 컴포넌트 설치

자, 이제 진짜 설치할 시간이에요! 패키지 목록을 업데이트하고 필요한 것들을 설치해봅시다:

```bash
sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl
```

쿠버네티스는 컨테이너를 돌리려면 컨테이너 런타임이 필요한데요, 우리는 containerd를 쓸 거예요:

```bash
sudo apt-get install -y containerd
```

containerd 기본 설정을 만들어줍니다:

```bash
sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml
```

⚠️ 여기 중요한 부분이에요! containerd 설정 파일에서 `SystemdCgroup`을 `true`로 바꿔줘야 해요:

```bash
# 설정 파일 수정 (sed로 자동 변경)
sudo sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
```

또는 직접 편집하려면:

```bash
# 설정 파일 열기
sudo nano /etc/containerd/config.toml

# [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options] 섹션에서
# SystemdCgroup = false를 SystemdCgroup = true로 변경
```

설정을 바꿨으면 containerd를 재시작해주고 부팅 시 자동 시작되도록 설정해줍니다:

```bash
sudo systemctl restart containerd
sudo systemctl enable containerd
```

## 3. 마스터 노드 초기화

### 네트워크 설정

쿠버네티스 클러스터가 제대로 통신하려면 몇 가지 네트워크 설정이 필요해요!

```bash
# 필요한 커널 모듈 로드
cat <<EOF | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF

sudo modprobe overlay
sudo modprobe br_netfilter

# 필수 sysctl 설정
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF

# 설정 적용
sudo sysctl --system
```

### kubeadm을 사용한 초기화

드디어 클러스터를 초기화할 시간이에요! 🎉 이 명령어 하나면 됩니다:

```bash
sudo kubeadm init --pod-network-cidr=192.168.0.0/16
```

> 💡 `--pod-network-cidr=192.168.0.0/16`는 나중에 설치할 Calico 네트워크 플러그인의 기본 설정이에요.

초기화가 끝나면 (좀 시간 걸려요, 커피 한 잔 하세요 ☕) kubectl 설정 파일을 내 계정으로 복사해줍니다:

```bash
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

## 4. 네트워크 플러그인(CNI) 설치

쿠버네티스는 Pod들끼리 통신하려면 네트워크 플러그인(CNI)이 필요해요. 우리는 가장 많이 쓰이는 Calico를 설치할 거예요:

```bash
# Calico 설치 (쿠버네티스 1.28과 호환되는 버전)
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml
```

> 💡 **버전 참고**: Calico v3.27은 쿠버네티스 1.25-1.29와 호환됩니다. 다른 버전을 쓰신다면 [Calico 공식 문서](https://docs.tigera.io/calico/latest/getting-started/kubernetes/)에서 호환 버전을 확인하세요!

설치가 끝나면 제대로 돌아가는지 확인해봅시다:

```bash
kubectl get nodes
kubectl get pods -A
```

노드 상태가 `Ready`로 나오면 성공! 🎉

## 5. 쿠버네티스 대시보드 설치

### 대시보드 배포

이제 웹 UI로 클러스터를 볼 수 있는 대시보드를 설치해볼게요. 터미널만 보면 좀 답답하잖아요? 😅

```bash
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml
```

### 관리자 계정 및 권한 생성

대시보드에 로그인하려면 관리자 계정이 필요해요. 만들어봅시다:

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

로그인할 때 필요한 토큰을 만들어주세요:

```bash
# 임시 토큰 생성 (기본 1시간 유효)
kubectl -n kubernetes-dashboard create token admin-user
```

💡 **팁**: 위 명령어는 임시 토큰을 만들어요. 만료되면 다시 실행하면 됩니다!

영구 토큰을 원하신다면 (쿠버네티스 1.24 이전 방식):

```bash
kubectl -n kubernetes-dashboard create token admin-user --duration=87600h
```

### 대시보드 접근 설정

대시보드를 외부에서도 볼 수 있게 서비스 타입을 NodePort로 바꿔줄게요:

```bash
kubectl -n kubernetes-dashboard edit svc kubernetes-dashboard
# type: ClusterIP를 찾아 type: NodePort로 변경
```

어떤 포트로 뚫렸는지 확인해볼게요:

```bash
kubectl get svc -n kubernetes-dashboard
```

이제 `https://<서버_IP>:<NodePort>`로 접속하면 멋진 대시보드가 보일 거예요! 🎨

## 6. 모니터링 스택 구축 (Prometheus, Grafana, Loki)

### Helm 설치

모니터링 툴들을 쉽게 설치하려면 Helm이 있으면 정말 편해요. 쿠버네티스의 npm 같은 거라고 생각하시면 돼요!

```bash
curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
chmod 700 get_helm.sh
./get_helm.sh
```

잘 설치됐는지 확인:

```bash
helm version
```

### Grafana 스택 설치

이제 Grafana 리포지토리를 추가해줍니다:

```bash
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update
```

한 방에 Loki, Prometheus, Grafana를 다 설치해봅시다! 🚀

```bash
helm install loki-stack grafana/loki-stack \
  --namespace monitoring --create-namespace \
  --set grafana.enabled=true \
  --set prometheus.enabled=true \
  --set prometheus.server.persistentVolume.enabled=false \
  --set promtail.enabled=true \
  --set grafana.service.type=NodePort
```

> 💡 `persistentVolume.enabled=false`는 테스트 환경이라 이렇게 했어요. 진짜 프로덕션에서는 영구 저장소를 쓰는 게 좋습니다!

설치가 잘 됐는지 체크해봅시다:

```bash
kubectl get pods -n monitoring
kubectl get svc -n monitoring
```

### Grafana 접근

Grafana가 어떤 포트로 떴는지 확인해볼게요:

```bash
kubectl get svc -n monitoring
```

기본 로그인 정보는 이렇게 확인해요:

- 사용자: admin
- 비밀번호: 아래 명령어로 확인!

```bash
kubectl get secret --namespace monitoring loki-stack-grafana -o jsonpath="{.data.admin-password}" | base64 --decode
```

이제 `http://<서버_IP>:<NodePort>`로 접속하면 멋진 Grafana를 볼 수 있어요! 📊

### 대시보드 설정

Grafana에 로그인했으면 이제 예쁜 대시보드를 추가해봅시다:

1. Home > Connections > Add new connection으로 가서
2. Loki 데이터 소스를 연결하고
3. Grafana.com에서 "Node Exporter Full" 같은 멋진 대시보드들을 가져오면 끝! 완전 간단하죠? 😎

## 7. 트러블슈팅 및 팁

### 마스터 노드에 Pod 스케줄링 허용

기본적으로 마스터 노드에는 Pod가 안 뜨게 되어 있어요. 근데 우리는 개발용이니까 이 제한을 풀어줄 수도 있어요:

```bash
# taint 확인
kubectl describe node <노드명> | grep Taint

# taint 제거
kubectl taint nodes <노드명> node-role.kubernetes.io/control-plane-
```

### 설치 초기화 (필요 시)

뭔가 꼬여서 처음부터 다시 시작하고 싶을 때는 이렇게 하면 돼요 (가끔 그럴 때 있죠 😅):

```bash
sudo kubeadm reset -f
sudo rm -rf ~/.kube /etc/kubernetes /var/lib/etcd /etc/cni/net.d
sudo systemctl restart containerd
sudo systemctl restart kubelet
```

### 외부 접근 설정

집 밖에서도 접속하고 싶다면 몇 가지 방법이 있어요:

**방법 1: SSH 터널링** (가장 안전)

```bash
# 로컬 PC에서 실행
# 대시보드 접근 (실제 NodePort로 변경하세요)
ssh -L 8443:localhost:<NodePort> username@server_ip

# Grafana 접근 (실제 NodePort로 변경하세요)
ssh -L 3000:localhost:<NodePort> username@server_ip
```

**방법 2: NodePort 사용** (개발 환경)

이미 우리가 설정한 NodePort를 사용하면 `https://<서버공인IP>:<NodePort>`로 바로 접근 가능해요.
단, 방화벽에서 해당 포트를 열어줘야 합니다!

**방법 3: kubectl port-forward** (임시 테스트용)

```bash
# 대시보드
kubectl port-forward -n kubernetes-dashboard service/kubernetes-dashboard 8443:443 --address=0.0.0.0

# Grafana
kubectl port-forward -n monitoring service/loki-stack-grafana 3000:80 --address=0.0.0.0
```

---

자, 여기까지 따라오시느라 수고하셨어요! 🎉 

이제 여러분만의 쿠버네티스 클러스터가 생겼네요. 물론 진짜 프로덕션 환경에서는 보안, 고가용성, 백업 같은 것들을 더 신경 써야 하지만, 일단 기본은 다 갖춰졌으니 이제 재미있게 실험해보세요!
