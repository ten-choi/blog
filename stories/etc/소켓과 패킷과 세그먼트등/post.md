osi 7계층 데이터 계층 전달

tcp, ip stack 에 관한 계층 데이터 전달

어플리케이션레이어

header
data

트랜스포트레이어의 전달형태
header
s.prot , d.port
header
data

인터넷 레이어

에서 송수신되는 데이터는 ip datagram or ip packet이라고 부름

header
s.ip address
d.ip address
header
s.prot , d.port
header
data

링크 레이어

header
header
s.ip address
d.ip address
header
s.prot , d.port
header
data
trailer

노드끼리 사용되는건 절달
