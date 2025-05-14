쿠버네티스 강의 보며 진해응ㄹ 해봅시다

제 경우엔는 minipc 로 서버를 준비했습니다

리눅스 24 라 지원이 안된다

리눅스를 자기나라 시간에 맞게 설정한다

apt-get update가 바로 안되기때문에 1.30 버전을 구글 클라우드의 공개 사이닝 키를 다운로드한다 1.30 버전을 쿠버 공식사이트에서 찾아서 사이닝키적용하는것이 좋다
gpt로 찾아서 넣을때 내 경우에는 실패했다

쿠버 레포지토리를 추가한다

이것의 경우에도 pkgs를 써야한다 새로운 패키지저장소? 암튼 이거 아니면 실패한다 공홈에서 구글 클라우드꺼 받으러가도 파일이 존재하지않아 에러가 발생한다
echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/v1.28/deb/ /" | sudo tee /etc/apt/sources.list.d/kubernetes.list

공홈 링크다 여기서 v1-30 이라고있는데 여기서 숫자만바꿔서 접근하자
https://v1-30.docs.kubernetes.io/docs/setup/production-environment/tools/kubeadm/install-kubeadm/#installing-kubeadm-kubelet-and-kubectl

그럴경우 문제없이 apt-get update가 완료된다

sudo apt-get update
sudo apt-get install -y kubelet kubeadm kubectl
sudo apt-mark hold kubelet kubeadm kubectl

이제 인스톨하고 위의 3개버전을 고정하자

인스톨이 완료되었다면 sudo apt-get install -y containerd 를 다운로드한다

설정을 초기화 하기위해 아래처럼 config를 만든다

sudo mkdir -p /etc/containerd
containerd config default | sudo tee /etc/containerd/config.toml
sudo systemctl restart containerd
sudo systemctl enable containerd

컨테이너드의 기본설정을 초기화한다 나도 컨테이너드는 안써봐서 아직모른다

✅ 3. 마스터 노드 초기화 (kubeadm init)
기본적인 초기화 명령 예시:
이걸로 네트워크 설정이 됩니다
sudo kubeadm init --pod-network-cidr=192.168.0.0/16

--pod-network-cidr는 나중에 설치할 CNI (예: Calico, Flannel 등)에 따라 정해집니다. Pod용 가상 IP 대역을 지정한 것입니다.
192.168.0.0/16 은 Calico에서 일반적으로 사용하는 범위입니다.

📌 실행이 완료되면 다음과 같은 출력이 나옵니다:

kubeadm join ... → 워커 노드를 클러스터에 연결할 때 사용하는 명령

/etc/kubernetes/admin.conf → API 서버 접속 인증정보

아래와같은 ip포워딩 문제가 발생할수있다
설정이 꺼져있어서 그런거니까
sudo sysctl -w net.ipv4.ip_forward=1 설정으로 켜두면된다

[ERROR FileContent--proc-sys-net-ipv4-ip_forward]

재부팅시 적용되게 설정해두자
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

그후에 kubeadm을 실행해서 pod를 만들었고 이상없이 실행되었다
sudo kubeadm init --pod-network-cidr=192.168.0.0/16

유저명 폴더에 숨김 폴더하나를 만들자 kube라고 만들고 쿠버네티스 admin 컨피스 파일을 넣어놓는다
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

calico.yaml은 Calico 네트워크 플러그인을 설치하기 위한 Kubernetes 리소스 정의 파일이야.
Kubernetes 클러스터에서 Pod 간 통신을 제어하고, 네트워크 정책(NetworkPolicy) 적용을 가능하게 해주는 CNI 플러그인
알아보니까 3.27이 lts이기도하고 쿠버 1.30 의 테스트가끝난버전이라고해서 적당한 버전이라 이걸로 결정

kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml

실행했는데 SystemdCgroup = false 로 되어있으면 문제가된다
이 불일치때문에 kube에서 etcd, kube-apiserver, kube-proxy 등 컨트롤 플레인 컴포넌트가 CrashLoopBackOff
kubectl 도 API 서버에 연결 못 해서 "connection refused" 라고 한다
SystemdCgroup = false를 true로 바꿔주자

          [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
            BinaryName = ""
            CriuImagePath = ""
            CriuPath = ""
            CriuWorkPath = ""
            IoGid = 0
            IoUid = 0
            NoNewKeyring = false
            NoPivotRoot = false
            Root = ""
            ShimCgroup = ""
            SystemdCgroup = false

sudo systemctl restart containerd
리스타트해준다

다 지우고 다시 시작하는게 첫설정에 꼬였다면 밀고 다시하는게 낫다 처음이기에 가능한 방법이다
sudo kubeadm reset -f
sudo rm -rf ~/.kube /etc/kubernetes /var/lib/etcd /etc/cni/net.d
sudo systemctl restart containerd
sudo systemctl restart kubelet

그리고 다시 kubeadm 초기화를 진행한다
sudo kubeadm init --pod-network-cidr=192.168.0.0/16

다시 진행한다
mkdir -p $HOME/.kube
sudo cp /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config

Calico CNI 설치
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.27.0/manifests/calico.yaml

다시 이걸하고 kubectl get node 를한다

kubectl get nodes
kubectl get pods -A

이러면 ready상태가 되는것을 확인할수있다

자이제 쿠버 대시보드를 설치해봅시다

대시보드 설치
kubectl apply -f https://raw.githubusercontent.com/kubernetes/dashboard/v2.7.0/aio/deploy/recommended.yaml

2️⃣ Admin 권한을 가진 ServiceAccount 생성 (필수)

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

3️⃣ 토큰 가져오기 (Dashboard 로그인용)
kubectl -n kubernetes-dashboard create token admin-user

kubectl port-forward -n kubernetes-dashboard service/kubernetes-dashboard 8443:443
에러가 나올것이다

taint 는 쿠버네티스에서 특정노드에 마음대로 pod 가 스케줄되지않게 하는 기능입니다
그리고 저는 마스터노드로 진행하고있기때문에 이런현상이 발생할수밖에없습니다
즉 아래와 같은 팬딩은 당연한 결과입니다 쿠버는 기본적으로 마스터 노드에 pod를 부여하지않고싶기때문입니다
yeol@ubuntu:~$ kubectl get pods -n kubernetes-dashboard -o wide
NAME READY STATUS RESTARTS AGE IP NODE NOMINATED NODE READINESS GATES
dashboard-metrics-scraper-795895d745-bnr2r 0/1 Pending 0 8m24s <none> <none> <none> <none>
kubernetes-dashboard-56cf4b97c5-8tc2m 0/1 Pending 0 8m24s <none> <none> <none> <none>

하지만 지금은 개발환경의 경우이기때문에 taint 설정을 해제합시다
kubectl describe node ubuntu | grep Taint
했을때 Taints: node-role.kubernetes.io/control-plane:NoSchedule 가 나오면 taint가 존재하는 상태입니다

아래의 코드로 삭제합니다 -는 필요한 코드입니다 오타아님
kubectl taint nodes ubuntu node-role.kubernetes.io/control-plane-

삭제했으면 10-20초안에 팬딩이 러닝으로 바뀌어야 정상
kubectl get pods -n kubernetes-dashboard -w

이제 다시 이거 해봅시다

kubectl port-forward -n kubernetes-dashboard service/kubernetes-dashboard 8443:443

이제 정상적으로 실행이 가능합니다

이제 local에서는 접근가능합니다 따라서 외부에서 접근을해야합니다 하지만
kubectl port-forward -n kubernetes-dashboard service/kubernetes-dashboard 8443:443
이거는 로컬전용이라 다른 컴퓨터에서 접근할수없습니다
외부용으로 뚫어줄수있지만 보안상

로컬과 타켓서버를 접근할수있는 설정으로 해줍시다
→ "내 로컬의 8443" 포트 → "원격 서버의 8443 포트"로 연결
ssh -L 8443:localhost:8443 yeol@100.124.15.63

그리고 https://localhost:8443 에 접근한뒤 생성해두었던 admin-user 토큰으로 로그인하면 접근이 가능하다

이제 모든 pods를 봐보자
kubectl get pods --all-namespaces

1️⃣ Kubernetes + CNI는 내부적으로 iptables를 자동 구성함
그렇기때문에 수동설정할일이 거의없다고함

이제 프로메테우스, 그라파나, 로키 를 써서 컴퓨터의 스펙과 로그를 모니터링 하려고합니다

helm을 먼저 다운로드 해줍시다 이것은 쿠버네티스의 패키지매니저입니다

쿠버 1.30 버전에서 helm으로 설치했을때 위의 스택 문제없는걸 확인했습니다
https://helm.sh/docs/intro/install/

helm에서 ㅈ같이 하기싫으면 아래처럼 하라고한다

$ curl -fsSL -o get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
$ chmod 700 get_helm.sh
$ ./get_helm.sh

Yes, you can curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash if you want to live on the edge.

인스톨을 완료해줬다
helm version
버전 확인하면 완료된다

이제 그라파나 사이트로 가자
https://grafana.com/docs/grafana/latest/setup-grafana/installation/helm/

아래 2개를 해서 문제없으면된다 추가하고 업데이트한다는소리다
helm repo add grafana https://grafana.github.io/helm-charts
helm repo update

그라파나 홈사이트에서 찾아보면 차트 어떻게 만들지는 샘플이 다있기때문에 나중에 임포트하면됨

이걸로 그라파나에 로키를 인스톨한다
helm install loki-stack grafana/loki-stack \
 --namespace monitoring --create-namespace \
 --set grafana.enabled=true \
 --set prometheus.enabled=true \
 --set promtail.enabled=true

이제 네임스페이스 monitoring을 사용하여 pods를 봐보자 시간이 지나면 Running으로 되면 문제없다
kubectl get pods -n monitoring

그럼이제 또 똑같이 로컬에서만 접근가능한 모니터링 그라파나를 실행하자자
kubectl port-forward -n monitoring service/loki-stack-grafana 3000:80

그리고 3000번으로 설정하면 ssh로 먼곳에서도 접근이 가능하다
ssh -L 3000:localhost:3000 yeol@100.124.15.63
하지만 슬슬 답답하다 쿠버 대시보드까지는 그럴수있지만 내가 왜 cmd로 이래야하는가 다뚫어놓는게 편하다
어차피 개발용 미니피씨이기때문이다 --set grafana.service.type=NodePort 이걸해주면된다

ClusterIp, NodePort, LoadBalancer 이렇게 3개라면 원래 ClusterIp는 디폴트지만 외부접근이안된다

그래서 NodePort로변경해준다

helm upgrade loki-stack grafana/loki-stack -n monitoring --set grafana.service.type=NodePort

grafana접근을해보자 외부에서 하지만안된다 위의 명령어에는 grafana.enabled=true 가 없었기때문이다
다시업데이트해주자 아이에 namespace를 지정해서 업그레이드하고 nodePort부분만 별도로 추가 설정해주었다

helm upgrade loki-stack grafana/loki-stack \
 -n monitoring \
 --set grafana.enabled=true \
 --set grafana.service.type=NodePort \
 --set prometheus.enabled=true \
 --set promtail.enabled=true

아래 명령어로 확인하면 monitoring 네임스페이스의 service 라는 pods를 연결해놓은 보이는데 garafana가 여기서 nodePort로 보이면 된다
kubectl get svc -n monitoring

위의 명령어로 나온 port를 붙여서 http + ip + port 로 하면 접근가능하다 어카운트 정보는 아래와같다
id: admin
pw찾는 명령어
kubectl get secret --namespace monitoring loki-stack-grafana -o jsonpath="{.data.admin-password}" | base64 --decode

Home
Connections
Add new connection
여기서 loki 검색하면 바로나온다 로키를 추가해보자 TODO 이거 왜하는지 이유 아직모른다

https://grafana.com/grafana/dashboards/
에서 Node Exporter Full 를 임포트해보자

내경우엔 badgatway 가 발생했다
쿠버의 it명령어를 통해 garafana에서 외부에 접근가능한지 확인해보자
내가 쓰고이있는 그라파나 찾기
kubectl get pod -n monitoring -o wide | grep grafana

kubectl exec -n monitoring -it 그라파나id넣기 -- curl -s https://grafana.com
it로 접근했기때분에 pods내부에서 외부로 접근해보기
wget -q --spider https://grafana.com && echo "✅ 인터넷 연결됨" || echo "❌ 인터넷 안 됨"

접근실패함 이걸뚫어서 뭘한다 X 그냥 load가 아니라 Json으로 받아서 적용하자 O를 선택하자
지금은 이걸로 진행만해도된다

여기서 문제는 임포트를 했어도 프로메테우스를 확인못하고있을것이다
확인하러가자

kubectl get svc -n monitoring

내경우에는 아래처럼 프로메테우스의 문제점을 찾아보았다
kubectl describe pod -n monitoring loki-stack-prometheus-server-123123

Prometheus가 실행되기 위해 필요한 디스크(PVC) 를 요청했는데,
Kubernetes가 해당 PVC(PersistentVolumeClaim)를 만족시켜줄 PersistentVolume(PV)를 찾지 못했다는 뜻입니다.
여기서 pvc는 디스크를 쓰기위한 객체이다 지속 볼륨클레임의 약어로 pod에 그게 있어야 디스크 사용이가능하고 자동바인딩이된다
즉 Loki나 그라파나는 메트릭데이터를 보존해야되는데 디스크에 접근할수없어서 보존이안되기때문에 문제인듯하다

하지만 나는? 지금 pvc를 만들필요가없으니 램으로 떼우자 장기보존데이터를 볼맘이 지금은 없다

helm upgrade loki-stack grafana/loki-stack \
 -n monitoring \
 --set grafana.enabled=true \
 --set grafana.service.type=NodePort \
 --set prometheus.enabled=true \
 --set prometheus.server.persistentVolume.enabled=false \
 --set promtail.enabled=true

그럼이제 다시 prometheus를 확인하자 pvc가없으니 재기동하면 정보날아갈수도있겠다고생각이든다
kubectl get pods -n monitoring | grep prometheus
러닝하고있으면이제 문제없이 사용할수있다

초반에 진행했던 쿠버 대시보드도 이제 쓸데없이 ssh 로 떼우지말고 nodePort로 바꿔주자
kubectl port-forward -n kubernetes-dashboard service/kubernetes-dashboard 8443:443
위처럼 실행했었던부분을 svc를 확인하면clusterIp가 되있을것이다
kubectl get svc -n kubernetes-dashboard
helm은 쿠버의 패키지 관리 매니저이지만 쿠버대시보드는 helm없이 수동으로 설치된리소스이기때문에 수정도 수동으로해야한다
kubectl -n kubernetes-dashboard edit svc kubernetes-dashboard
위의 명령어를 실행하면 수정 파일의 vi가 나오기때문에 아래처럼 수정후 저장한다
type: ClusterIP -> type: NodePort
노드포트로 변경했다면 다시 svc를 확인하자 port가 새로 나왔을것이다
그러면 토큰도 재발급해야할것이다

4코어짜리 샀는데 생각보다 cpu가 힘이없다.. 지금 60퍼를 먹고있다고 생각했는데 처음 기동 문제였던거같다 점점 낮아진다 45에서 8.7로 내려왔다..
다행이다 4코어 개쌉애바인줄알았다..

걱정이 이만 저만