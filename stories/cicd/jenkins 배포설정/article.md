![Description](https://img.notionusercontent.com/s3/prod-files-secure%2F6ab3efe6-44b5-4e5c-9d86-56543fb7f59d%2Fc3b86c80-eaba-4a31-971d-868a2b179849%2Ftest2.jpg/size/w=1420?exp=1727749267&sig=VX63E66yaxZvLTyfE2Db1fyK5g_lgajo6O10Oikoyq0)

<!-- pre image 설정해야하나 위처럼 -->

## What is the mongoDb

젠킨스 배포설정

젠킨스를 install 할 linux를 준비한다

manager 프로그램으로 install을 하면
gui가 보인다

젠킨스 로그인과 유저 계정을 생성한다

모든화면을 로그인하면 기본적인상태가 나온다

거기서 프리스타일로 jenkins를 만든다

cicd 만 할거기때문에 대부분의 설정은 프리스타일로 진행한다

github권한을 설정하고

프로젝트에서 aws config가 필요할경우 해당 linux에서 미리 aws confiugre을 설정한다
aws configure은 aws에서 pem.key를 설정한다.






sudo docker cp ./hange-alliance-0.0.1-SNAPSHOT.war 241f7a4ceef6:/usr/local/tomcat/webapps/hange-alliance.war


docker run -d -p 8080:8080 --name my-tomcat-server -v ~/.aws:/root/.aws tomcat:11-jdk17


setenv
export CATALINA_OPTS="$CATALINA_OPTS -agentlib:jdwp=transport=dt_socket,address=*:5005,server=y,suspend=n -Dspring.profiles.active=alpha"





### ✅ 가장 먼저 확인할 것: jenkins 사용자의 subuid/subgid 설정
jenkins 사용자에게 컨테이너 내부에서 사용할 보조 ID(subuid/subgid)가 할당되어 있는지 확인해야 합니다.

아래 명령어를 실행해 보세요.

Bash

grep jenkins /etc/subuid /etc/subgid
만약 아무것도 출력되지 않는다면, 이것이 바로 문제입니다. jenkins 사용자는 컨테이너를 만들 권한이 없는 것입니다.

### 해결 방법
root 권한으로 다음 명령어를 실행하여 jenkins 사용자에게 subuid/subgid 범위를 할당해 주세요.



 echo "3MnXjj6QLN" | docker login registry.example.com -u choi_yeol --password-stdin
sudo docker build -t registry.example.com/rebirth/hange-alice:latest .
sudo docker push registry.example.com/rebirth/my-app:latest



jenkins는 docker를 만들 권한이없어서 추가해줘야한다
sudo usermod --add-subuids 100000-165535 jenkins
sudo usermod --add-subgids 100000-165535 jenkins