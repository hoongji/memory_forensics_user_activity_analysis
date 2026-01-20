# Memory Forensics: User Credential Recovery from Windows 7 Memory Dump

### Windows 7 메모리 덤프에서 사용자(john)의 비밀번호를 복구하기 위해 
lsass.exe 기반 자격 증명 분석을 수행하고, 
Volatility 3의 한계를 확인한 뒤 Volatility2 로 전환하여 
NTML 해시를 추출, 평문화한 메모리 포렌식 사례 분석 프로젝트
---

## 프로젝트 개요 
### 1.1 분석 목적
해당 프로젝트는 포트폴리오2 에서 사용한 동일한 메모리 덤프를 대상으로, 단순 시스템 상태 확인이 아닌 사용자 행위 및 인증 정보 분석을 목표로 한다.(?)
특히, 메모리 덤프의 사용자로 추정되는 "john의 비밀번호"를 복구하는 것을 최종 목표로 설정하였다. 
