자 이제 앱을 실행하기위해 몽고나 고랭같은 was를 올려봅시다
일단 mongo를 추가하려합니다 mkidr로 적당한 yaml 용 폴더를 만들어줍니다
아래같은 파일을 추가합니다다

📁 mongo-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
name: mongodb
labels:
app: mongodb
spec:
replicas: 1
selector:
matchLabels:
app: mongodb
template:
metadata:
labels:
app: mongodb
spec:
containers: - name: mongodb
image: mongo:7
ports: - containerPort: 27017
volumeMounts: - name: mongo-storage
mountPath: /data/db
volumes: - name: mongo-storage
emptyDir: {} # 운영 환경에서는 PVC로 교체 권장

📁 mongo-service.yaml
apiVersion: v1
kind: Service
metadata:
name: mongodb
spec:
selector:
app: mongodb
ports:

- port: 27017
  targetPort: 27017
  type: NodePort

왜 2개냐면 하나는 실행하고 재시작관리하는 역할이고 또하나는 클러스터 내에 dns를 제공해고 다른앱이 접근할수있게 해줌
파일을 추가후 kube에서 실행합니다
kubectl apply -f mongo-deployment.yaml
kubectl apply -f mongo-service.yaml

이제 확인해주자
kubectl get pods
kubectl get svc

실행이 완료되면 다른 pod에서 mongodb://mongodb:27017 이런식으로 url접근이가능하다
그리고 나는 nodePort로 설정했다 외부에서 mongo를 확인하고싶기때문이다
나는 내 기기이외에 외부접근이 어렵기때문에 몽고의 어카운트가 별도로 없지만 외부공유가 시작되는경우
보안상 필요하다, 이제 몽고 실행이 완료되었다

이제 본인의 서버를 실행한다 나의 경우 고랭을 적용해야겠다

간단한 서버는 알아서 만든다
아래 파일을 위치에 맞게 만들고 root에 Dockerfilc도만들어준다
github action에서 ci가 일어나고 docker image파일을 dockerhub에 릴리즈 한후 배포는 kuber에서 dockerhub를를 pull할것이다
.github/workflows/docker.yml
Dockerfile

docker.yml 을만들때 주의할점

1. dockerhub에 레포지토리를 미리 만들어둔다 public 은 언제나 무료이다
2. action은 2000분 무료였던거로 기억한다 개인이 테스트용으로 할땐 왠만하면 3분짜리를 한달에 500번 배포해도 유료가되기어렵다
3. github action secret에 dockerhub의 정보를 넣어서 yml을 만들어야 정보노출없이 사용가능하다

위와같이 배포를 성공했다면 다음으로 넘어갈수있다

쿠버에서 사용할 yaml 파일을 만들어서 고랭을 기동시켜보자

dockerhub는 Always로 적용해놨기때문에 문제없이 가능해

이제 문제는 고랭을 시작해야되는데 민감정보처리를 어떻게하면좋을까 고민했어
나는 무료니까 aws 쪽은 안쓸거야 그래서 bitnami같은것도 고려했지만 과해

githubaction에 넣는 방법도있지만 그러면 깃허브액션에서 내 쿠버에 접근해야하는데 나는 포트포워딩을 할수없는 공유기환경이였고
외부에 노출할 이유가 없기때문에 tailscale을 써서 내 우분투서버를 사용하고있다
즉 깃허브액션에서 접근할수없는 환경이라는거지
고민을해본결과 간단한 파일이동 명령어를 하나 만들어서 배포전에 리눅스 파일에 업로드 하는 방식을 택했어
개발환경이니까 이렇게 하지만 외부도 뚫었으면 Cloudflare Tunnel로 ip자체를 오픈한다면 보안적인 부분 신경쓸부분이 많아지겠지만
깃허브액션에서 쿠버민감정보 설정후 쿠버 동작까지를 깃액션에서 가능하겠지

이건 내 개인프로젝트들이 어느정도 가닥을잡고해도 늦지않다는 판단
명령어로 sh하나만들어서 업데이트해도 괜찮을거라는 방향으로감

결국 쿠버에서는 configmap을 만들어서 dployment실행할때 참조시킬수밖에없음 즉 푸시했다고 자동으로 실행되게하려면
로컬에서 configmap을 배포하는 sh명령어를 만들고 배포하면 될듯하다
