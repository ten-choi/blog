# 보안 가이드 모음

현대 웹 애플리케이션 개발에 필요한 핵심 보안 개념들을 정리한 가이드입니다.
각 가이드는 실무에서 바로 적용할 수 있는 예제 코드와 베스트 프랙티스를 포함합니다.

---

## 📚 가이드 목록 (중요도 순)

### 1. [API Security](./api-security-guide-kr.md) ⭐️⭐️⭐️⭐️⭐️
REST API, GraphQL 등 API 통신 보안 - Rate Limiting, CORS, Injection, CSRF, XSS 방어

### 2. [Authentication & Authorization](./authentication-security-guide-kr.md) ⭐️⭐️⭐️⭐️⭐️
사용자 인증과 권한 관리 - JWT, OAuth 2.0, Session, MFA, RBAC, ABAC

### 3. [Application Security](./application-security-guide-kr.md) ⭐️⭐️⭐️⭐️
애플리케이션 코드 레벨 보안 - Session 관리, 파일 업로드, 보안 헤더, 에러 처리

### 4. [Infrastructure Security](./infrastructure-security-guide-kr.md) ⭐️⭐️⭐️⭐️
서버, 컨테이너, 클라우드 인프라 보안 - Docker, Kubernetes, AWS/Azure/GCP, 서버 하드닝, CI/CD 보안

### 5. [Secrets & Key Management](./secrets-management-guide-kr.md) ⭐️⭐️⭐️
API 키, 비밀번호, 암호화 키 관리 - 환경 변수, AWS Secrets Manager, HashiCorp Vault, Azure Key Vault

### 6. [Network Security](./network-security-guide-kr.md) ⭐️⭐️⭐️
네트워크 레벨 보안 설정과 공격 방어 - 방화벽, VPN, DDoS 방어, DNS 보안, TLS/SSL

### 7. [Database Security](./database-security-guide-kr.md) ⭐️⭐️⭐️
데이터베이스와 데이터 저장소 보안 - 암호화(at rest/in transit), 접근 제어, 백업 보안, 감사 로깅

### 8. [Frontend Security](./frontend-security-guide-kr.md) ⭐️⭐️⭐️
클라이언트 사이드 보안과 브라우저 보안 - XSS, DOM-based 취약점, CSP, SRI, Third-party script 관리

### 9. [Logging & Monitoring](./logging-monitoring-guide-kr.md) ⭐️⭐️⭐️
보안 이벤트 로깅, 모니터링, 인시던트 대응 - Winston, ELK Stack, Prometheus, Sentry 활용

### 10. [Compliance & Privacy](./compliance-privacy-guide-kr.md) ⭐️⭐️
개인정보 보호 법규와 컴플라이언스 - GDPR, CCPA, PCI-DSS, HIPAA 준수 방법

### 11. [Supply Chain Security](./supply-chain-security-guide-kr.md) ⭐️⭐️
외부 라이브러리와 의존성 보안 - npm/pip 패키지 취약점, 악성 패키지 탐지, 오픈소스 라이선스 관리

### 12. [Secure Software Development Lifecycle](./ssdlc-guide-kr.md) ⭐️⭐️
보안이 통합된 개발 프로세스 - 보안 요구사항 정의, 코드 리뷰, SAST/DAST, CI/CD 파이프라인 보안

---

## 🎯 학습 가이드

### 초급자 (입문)
API와 인증부터 시작하여 기본 보안 개념 학습  
**1 (API Security) → 2 (Authentication) → 8 (Frontend Security) → 3 (Application Security)**

### 중급자 (실무 1-3년)
실무 필수 보안 영역 집중 학습  
**1 → 2 → 3 → 5 (Secrets Management) → 7 (Database) → 4 (Infrastructure) → 9 (Logging & Monitoring)**

### 고급자 (시니어/아키텍트)
전체 보안 생태계 이해 및 프로세스 통합  
**1 → 2 → 3 → 4 → 5 → 6 (Network) → 7 → 8 → 9 → 10 (Compliance) → 11 (Supply Chain) → 12 (SSDLC)**

### 특정 분야별 학습 경로
- **백엔드 개발자**: 1 → 2 → 3 → 5 → 7 → 4 → 6 → 9
- **프론트엔드 개발자**: 1 → 2 → 8 → 3 → 5 → 9
- **DevOps 엔지니어**: 4 → 5 → 6 → 9 → 11 → 12
- **보안 담당자**: 전체 숙지 (1-12)
