배포하기위한과정

kubeconfig를 확인하고 public 를 적용한 후 인코딩한다고한다
server: https://100.124.15.63:6443

수정하고 배포를 해보자

일단 에러나는 부분을 왠만하면 ai로 해결하고 넘어가서 실행까지를 가보자 정안된다 싶으면 그때 내가 분석하면서 진행하자

배포할때 시크릿에 설정한
Environment 명도 deploy.yml 에 기입을해줘야한다

deploy에 필요한 값들과 env를 깃허브 시크릿에 설정한다
필요한건 도커허브 유저닉네임, 토큰, 쿠버네티스 config의 base64정보, 쿠버네티스 네임스페이스(이건어차피 default긴한데 필요에 따라 달라질수있으니 넣자)

여기서 나는 포트포워딩이 불가능한 와이파이 환경이다 그리고 미니피씨만 가지고있다
개발자체는 tailscale로 가능하지만 githubaction등 외부의 cicd에 의존하는순간 내 서버에 접근이 불가능하다고 나올것이다

즉 쿠버네티스에서 restart해야한다면 githubaction에서 요청을 보내야한다

외부 접근이 6443포트에서도 가능하게 Forwarding HTTP traffic from https://app1.serveo.net 해당포트를 외부에 노출하는 방식을 채택했다
생각해보니 app1같은 test명이라도 누가쓰고있을법한데 자동으로 만들어진거 그냥쓰고있지만 왜 아무도 안쓰는걸까싶다
일단 무료로 해당 포트의 ip를 외부에 개방했다

쿠버네티스에서는 kubeadm.yaml이라는 파일을통해 가능하다

kubectl -n kube-system get configmap kubeadm-config -o jsonpath='{.data.ClusterConfiguration}' > kubeadm.yaml
위의 명령어로 기본값을 추가하고 아래는 SAN처리에서 내가 추가한 외부 도메인도 받겠다는 의미다

```
  certSANs:
    - 192.168.0.100
    - 10.96.0.1
    - app1.serveo.net
```

SAN에 해당 도메인이나 ip를 추가해야 쿠버에서도 허용해준다

sudo kubeadm init phase certs apiserver --config /home/yeol/.kube/kubeadm.yaml

이걸 해야한다 기존파일이 존재해서 안된다면 기존 의
sudo cp /etc/kubernetes/pki/apiserver.crt /etc/kubernetes/pki/apiserver.crt.bak
sudo cp /etc/kubernetes/pki/apiserver.key /etc/kubernetes/pki/apiserver.key.bak

sudo rm /etc/kubernetes/pki/apiserver.crt
sudo rm /etc/kubernetes/pki/apiserver.key

위의 적용을 해야한다 그리고 생성 해보면 생성된다

sudo systemctl restart kubelet

openssl s_client -connect localhost:6443 -showcerts | openssl x509 -text | grep -A1 "Subject Alternative Name"

확인해보면 내가 설정한 외부 ip가 등록된것을 알수있다

5월 8일차는 여기까지

5월 9일은 여기부터 진행한다

4시간을 써서 8시간을 버렸다 가성비가 좋지않다
오늘 집가는길에 양념치킨 먹어야겠당 2개 먹어야겠당 먹으면서 집가면서 아니 생각도 하지말아야겠다

# 포트포워딩 방법 비교 및 Serveo 사용 가이드

## 사용해 본 포트포워딩 서비스

- **Ngrok**: 사용해 봤으나 중간에 연결이 끊기는 문제가 있음
- **Tailscale**: 개발 과정에서 활용하기 좋음
- **클라우드 플레어**: 유료 서비스이며 도메인 구매가 필요함

## Serveo 사용법

Serveo는 개인 프로젝트를 무료로 외부에 노출시킬 수 있는 좋은 방법입니다. Ngrok과 달리 상대적으로 안정적인 연결을 제공합니다.

### 1. SSH 키 생성

```bash
# 2048비트 RSA 키 생성
ssh-keygen -t rsa -b 2048 -f ~/.ssh/serveo_rsa

# 생성된 공개키 확인
ssh-keygen -l -f ~/.ssh/serveo_rsa.pub
```

### 2. 포트포워딩 설정

```bash
# 단일 애플리케이션 포트포워딩
ssh -i ~/.ssh/id_rsa -R mini-tenc:80:localhost:8080 serveo.net

# 여러 애플리케이션 동시 포트포워딩
ssh -i ~/.ssh/serveo_rsa -R app1:80:localhost:3000 -R app2:80:localhost:4000 serveo.net
```

실행 시 다음과 같은 메시지가 표시됩니다:

```
Forwarding HTTP traffic from https://app1.serveo.net
Forwarding HTTP traffic from https://app2.serveo.net
```

## 사용 시나리오

- **개발 단계**: Tailscale 사용
- **프로젝트 공유 단계**: Serveo를 통한 외부 노출 (OpenAPI 공유 등)
- **실제 서비스 배포**: 도메인 구매 후 클라우드 플레어 등 고려

## 장점

- 개인 미니 PC를 사용하는 경우 유용
- 포트포워딩이 어려운 네트워크 환경에서 활용 가능
- 무료로 외부 노출 가능
