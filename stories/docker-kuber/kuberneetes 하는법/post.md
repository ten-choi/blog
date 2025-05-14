윈도우일경우 도커 데스크탑의 설정에서 쿠버네티스 설정을 온으로 변경한다.

아래 명령어로 kubernetes가 동작하는걸 확인할수있다
kubectl version

kubernetes는

minikube는 윈도우용으로 쿠버 사이트에서 인스톨 파일 다운로드해서 인스톨하면된다.
그러면 아래 명령얼로 다운로드 된것을 확인할수있다.

minikube version

minikube start --deriver=""

window일경우 아래처럼 인스톨이 가능하다
choco install kubernetes-cli
choco install minikube

권한문제가 나오면 powerShell에서 관리자 권한으로 다운로드 해야한다

minikube start --deriver=hyperv

virtualbox가안되어서 위에걸로 진행한다 아래걸 진행하면 쿠버네티스 현재상태를 대쉬보드로 확인할수있다
왜 hyperv를 설정했고 그게 어떤영향을끼치는 지는 아직 더 해봐야알듯하다
10 0000
minikube status
minikube dashboard

kubectl create deployment --name=kub-first-app
kubectl get pods
kubectl get deployments
kubectl delete first-app
