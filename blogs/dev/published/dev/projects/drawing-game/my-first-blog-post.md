---
title: My First Blog Post
published: false
description: This is my first blog post using the dev.to API
tags: beginners, tutorial, webdev
cover_image: https://example.com/your-cover-image.jpg
series: Getting Started with dev.to
---

1) Local Development Environment

PC / OS: Linux
Hardware: CPU 4 cores, RAM 16GB
2) Platform & Runtime
Container Orchestration: Kubernetes
In-cluster Runtime: (optional if you use it) containerd / Docker, Helm, Argo CD, etc.

3) Infrastructure Services

Cache / KV: Valkey

Database: MongoDB

4) Backend

Language: Go (Golang)

API: GraphQL

Architecture: (optional) monolith / microservices, clean architecture, hexagonal, etc.

5) Frontend

Framework: React

API Client: (optional) Apollo Client / urql / Relay

그림 게임을 만들자

의미없는건 만들기 싫고 그나마 쓸만한게 뭐가있을까 고민하고있다
그래서 친구들과 있을때 간단히 할만한게 뭐가있을까 고민중이다

이번 서버는 golang으로 진행하고 프론트는 react로 작업한다

1. ox 퀴즈
2. 그림 맞추기
3. ito 카드게임

golang으로 개발하고 있다 
기존에 

예전에 재미삼아서 써봤는데 go가 많이 뜨니까 golang으로 해도 좋을거같았다
웹으로 개발하고있지만 모바도 대응할지 아직 고민중이다
그래서 api스펙은 graphql로 해서 어느쪽이든 대응을 좀더 쉽게 하려고한다

서버나 컨테이너가 2개이상이 되는순간 websocket간의 소통이 어렵기때문에 redis의 무료버전인 valkey를 사용해서 진행한다

내가 백엔드 위주이긴 하지만 react는 개발경험도 있고 요새 ai로 대부분대응이 가능하여 보고 알기쉬운 react를 선택했다

먼저 draw.io에 기본적인 설계도를 만들었다 
1차적인 개발로는 간단하게 게임이 진행만 가능해도 괜찮을듯 하여 그렇게 진행하려고 한다


개발할때 에로사항이 있다면 golang의 경우에는 restapi + ws 를 사용할때 openApi + asyncApi를 생각했는데 asyncApi가 golang에서 호환이 잘안되는건지 html을 작성해야하는 경우가 발생했고 사양과 테스팅을 편하게 공유하기위한 툴이기때문에 html을 적고싶진않았다
그래서 더더욱 graphql이 되엇다

golang을 할때 controller가아닌 handler라는 표현을 사용하고 있는데 살짝 어색하다
이부분을 제외하고 프로젝트 설계는 3layer 아키텍처로 평소와 동일하게 진행하고 있다 

valkey는 무료인 redis 라고 생각하고 그냥 진행했다 별차이를 느끼지 못했다.
user정보에 관해 profile혹은 token정보가 생길경우 그것을 cache할 예정이다
이외에는 websocket의 brodcast용으로 사용할것이다 

Kubernetes 기반 조직(=요즘 빅테크/대기업 다수)의 CD 트렌드:
→ Argo CD / Flux 같은 GitOps CD를 많이 채택 
GitHub
+1

Kubernetes-native CI 트렌드:
→ Tekton 같은 K8s-native 파이프라인을 플랫폼 레벨에서 쓰는 사례가 증가 
Tekton

**“Jenkins → Tekton/Argo로 갈 때의 최소 구성(리포 구조/Helm/Kustomize/환경 분리)”**까지 딱 맞춰서 제안해줄게요.


일단 아래처럼 3개를 인스톨합시다 
dnf install containerd

cat <<'EOF' | sudo tee /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://pkgs.k8s.io/core:/stable:/v1.34/rpm/
enabled=1
gpgcheck=1
gpgkey=https://pkgs.k8s.io/core:/stable:/v1.34/rpm/repodata/repomd.xml.key
exclude=kubelet kubeadm kubectl cri-tools kubernetes-cni
EOF


dnf install kubelet kubeadm kubectl
kubeadm init
# CNI apply


sudo systemctl enable --now containerd
sudo systemctl restart containerd
sudo systemctl status containerd --no-pager

sudo systemctl enable --now kubelet
sudo systemctl restart kubelet
sudo systemctl status kubelet --no-pager


sudo ls -l /run/containerd/containerd.sock

sudo swapoff -a
free -h | grep -i swap



sudo sysctl -w net.ipv4.ip_forward=1
cat /proc/sys/net/ipv4/ip_forward
# should print: 1


cat <<'EOF' | sudo tee /etc/sysctl.d/99-kubernetes-cri.conf
net.ipv4.ip_forward = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
EOF

sudo modprobe br_netfilter
sudo sysctl --system

sysctl net.ipv4.ip_forward
sysctl net.bridge.bridge-nf-call-iptables


// 일단 이거 저장하지말고 토큰값이니까 가지고만있자
kubeadm 토큰이다
Then you can join any number of worker nodes by running the following on each as root:
 
kubeadm join 10.33.255.58:6443 --token 7z5gd9.hdyw5omp9ijfv2pc \
        --discovery-token-ca-cert-hash sha256:609edd1217530b9a1556488086fae274e00857c3e539fd5d0bedf1853210bafd
[www-web@vpocket-alpha-ap-0 sysctl.d]$


이거까지해서 kubectl연결함
getent hosts localhost
cat /etc/hosts
sudo sysctl net.ipv6.conf.all.disable_ipv6



KUBECONFIG=/etc/kubernetes/admin.conf kubectl get --raw=/readyz
KUBECONFIG=/etc/kubernetes/admin.conf kubectl get nodes




서버가 계속 부활하고 죽고를 반복했다 kube api server와 etcd 가 반복해서 죽었고 살아났다

일단 양쪽의 livenessProbe를 둘다 주석처리했다 

sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
sudo vi /etc/kubernetes/manifests/etcd.yaml

# livenessProbe:
#   failureThreshold: 8
#   httpGet:
#     host: 10.33.255.58
#     path: /livez
#     port: 6443
#     scheme: HTTPS
#   initialDelaySeconds: 10
#   periodSeconds: 10
#   timeoutSeconds: 15


api서버가 살아있을때 아래거를 연타해서 반복해서 설치해야한다 
CNI가 설치안되어있으니까 나머지 2개가 부활했다 죽는걸 반복하는데 api서버가 살아있을때 아래거를 설치해야하기때문에 그냥 연타해야한다 부활했을때

kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/calico.yaml




# 1. 기존꺼 삭제
kubectl delete statefulset mongo -n data
kubectl delete pvc mongo-data-mongo-0 -n data

# 2. 수정된 yaml로 다시 생성
kubectl apply -f mongo.yaml


# 1. 대기 중인 녀석들 삭제
kubectl delete statefulset valkey -n data
kubectl delete pvc data-valkey-0 -n data  # PVC 이름이 다를 수 있으니 'kubectl get pvc -n data'로 확인하고 지우세요

# 2. 수정된 설정으로 다시 시작
kubectl apply -f valkey.yaml


이쪽을 찾아봐야한다 이쪽에서 bind가 안되어서 한쪽은 ip허락했는데 한쪽은 허락하지않아서 에러가 발생하는경우가 있다 
이부분 확인해줘야한다 

 sudo vi /etc/kubernetes/manifests/kube-apiserver.yaml
 sudo vi /etc/kubernetes/manifests/etcd.yaml



echo "10.33.255.58 vpocket-alpha-ap-0 vpocket-alpha-ap-0.coconefk" | sudo tee -a /etc/hosts



API 서버는 시작할 때 "나는 누구인가?"를 확인하기 위해 자신의 호스트네임(vpocket-alpha-ap-0)으로 접속을 시도하는데, /etc/hosts에 정보가 없으니 접속할 곳을 찾지 못하고 "타임아웃"으로 죽어버린 것입니다.




===========================================


sudo kubeadm reset -f


전부 삭제하고 다시 설치했다

sudo systemctl stop kubelet
sudo systemctl stop containerd
sudo systemctl stop docker  # (만약 설치되어 있다면)

# 쿠버네티스 설정 파일 삭제

sudo dnf remove -y kubelet kubeadm kubectl containerd containerd.io kubernetes-cni
sudo rm -rf /etc/kubernetes/

# 사용자의 kubectl 설정 삭제
rm -rf $HOME/.kube/

# 핵심 데이터(etcd 포함) 삭제 - 아까 문제된 데이터가 여기 있습니다
sudo rm -rf /var/lib/etcd/
sudo rm -rf /var/lib/kubelet/
sudo rm -rf /var/lib/dockershim/
sudo rm -rf /var/run/kubernetes/

# 컨테이너 런타임 데이터 삭제
sudo rm -rf /var/lib/containerd/
sudo rm -rf /etc/containerd/
sudo rm -rf /run/containerd/

# 네트워크 설정(CNI) 삭제
sudo rm -rf /etc/cni/
sudo rm -rf /var/lib/cni/
sudo rm -rf /var/run/flannel/
sudo rm -rf /var/run/calico/

꼬여있는 네트워크 규칙을 초기화합니다.
sudo iptables -F && sudo iptables -t nat -F && sudo iptables -t mangle -F && sudo iptables -X

마운트해제 해야 삭제되는경우가 발생
sudo umount /var/run/calico/cgroup
sudo rm -rf /var/run/calico
sudo rm -rf /var/run/containerd/




---------------------------------------------
다시 설치를 해보자 


# Disable swap (recommended)
sudo swapoff -a
sudo sed -i.bak '/\sswap\s/s/^/#/' /etc/fstab



# Kernel modules + sysctl (needed for most CNIs)
cat <<'EOF' | sudo tee /etc/modules-load.d/k8s.conf
overlay
br_netfilter
EOF
sudo modprobe overlay
sudo modprobe br_netfilter

cat <<'EOF' | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
sudo sysctl --system


sudo sysctl --system 를 진행했을때 아래와 같은에러가 3개정도 나왔다
sysctl: setting key "net.ipv4.conf.all.rp_filter": Invalid argument

# 에러를 일으키는 부분
# net.ipv4.conf.all.rp_filter
# net.ipv4.conf.all.accept_source_route
# net.ipv4.conf.all.promote_secondaries



sudo vi /etc/sysctl.d/여기를 찾아보면 파일중에 위의 부분을 가진 부분이 존재한다
나는 00-defaults.conf 에 저 설정들이 있었고 주석처리를 해서 해결했다








---------------------------------------------



몽고를 설치한다

mongo.yaml + pv-mongo.yaml

mongo기본설치 + pv있어야 pod가 재기동되도 데이터가 남는다


아래처럼 데이터가 저장될곳을 만들고 권한 지정


sudo mkdir -p /data/mongo-0
sudo chown -R 999:999 /data/mongo-0
sudo chmod 777 /data/mongo-0






sc-manual.yaml   pvc가 어떤 방식의 디스크(스토리지)
 를쓸건지를 알려주는 설정이라는데 pvc는뭘까
쿠버네티스 PVC( Persistent Volume Claim)란? PVC는 stateless한 Pod이 영구적으로 데이터를 보존하고 싶은 경우 사용하는 리소스이



kubectl apply -f sc-manual.yaml
kubectl apply -f pv-mongo.yaml
kubectl apply -f mongo.yaml





valkey 만들기

sudo mkdir -p /data/valkey-0
sudo chmod 777 /data/valkey-0



----------------------------------------------


github에서 토큰만드기


golang에서 프롬프트에서  docker login ghcr.io -u yoru-choi
으로 login하고 password는 token을 사용합니다




 yoru-choi

dockerfile을 알맞게 만들어줍니다 

빌드합니다 
docker build -t go-server-local:latest .



# 로컬 이미지에 GHCR 주소 태그 적용
docker tag go-server-local:latest ghcr.io/yoru-choi/go-server-app:v1.0

# GHCR로 이미지 푸시
docker push ghcr.io/yoru-choi/go-server-app:v1.0



pull하고 kubectl에서 run하면 될듯

https://github.com/yoru-choi?tab=packages


푸시까지 완료


------------------------------------

젠킨스 cicd만들기

git token과 k8s의 token을 jenkins credientials 에 저장

git push 할때는 token값을 사용하여 jenkins에서 git으로 push한다

pull하고 deploy할때는 k8s의 값도 같이사용한다 


golang서버를 위한 yaml파일도 github에 추가하도록하다
k8s폴더를 만들고 deployment.yaml 을 만들어주자


WebSocket은 “유저(프론트)와 서버를 실시간으로 묶는 기술 이고
Valkey Pub/Sub는 “서버와 서버를 실시간으로 묶는 기술 이다.



기능,메서드,엔드포인트,주요 파라미터 / 필드,설명
사용자 생성,POST,/users,"nick_name, gender",초기 레벨(level)은 서버에서 1로 설정
사용자 조회,GET,/users/{id},"nick_name, gender, level",사용자 프로필 정보 반환

---------------------------


openApi처럼 보기쉽게 문서를 새ㅓㄴ하려고함 
http://localhost:8080/graphql


https://studio.apollographql.com/sandbox/explorer
대부분의 빅테크 개발자들이 문서화 공유할때 위에것을 사용한다는 내용을 ai를 통해서 확인하거 아래의 거를 install해서 테스트를 진행중이다 
 
http://vpocket-alpha-ap-0.coconefk:8080/query
http://alpha-vpocket-web.coconev.jp:30080/graphql



테스트결과 linux서버에서는 https가 필수로 필요하다
localhost에서는 가능하다

-> https가 적용되어야가능하다 아니면 localhost만 가능하다
그런데 프론트 백엔드가 갈려있는경우 이게 너무 불편해진다


로그인해서 공유하는 방법이 존재했다 

curl -sSL https://rover.apollo.dev/nix/install | sh


금욜에 정리하자 순서대로 진행해서 저걸로 스키마를 공유한다 그리고 나중에 퍼블리쉬만 한다 = 그러면된다 그경우 퍼블리쉬도 그냥 젠킨스에서 하자 이미지 빌드전에 그러면 문제없을듯?


