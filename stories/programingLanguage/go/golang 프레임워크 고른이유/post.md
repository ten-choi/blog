go 시작하는법

fasthttp 라는 package 를 사용하여 구현을 했다.

Gin, Echo는 Go 기본 내장된 net/http 를 사용하여 만들어졌다.

fasthttp 라는 package 를 사용하니까 당연히 문제점은

Go 언어가 업데이트 되면 fasthttp 가 업데이트 되어야하고

그에 따라 Fiber 도 업데이트 되어야 하는 이런식의 구조이다.

그래서 아마도 Gin, Echo 보다 업데이트가 늦지 않을까 하지만..

Fiber 개발자들이 일을 열심히 하는것 같다.

가장 큰 차이점은 fasthttp 를 사용한다는 점이라서 Fiber의 성능이 압도적이라고한다
