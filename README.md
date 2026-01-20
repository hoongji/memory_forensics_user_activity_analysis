# Memory Forensics: User Credential Recovery from Windows 7 Memory Dump

 Windows 7 메모리 덤프에서 사용자(john)의 비밀번호를 복구하기 위해 
lsass.exe 기반 자격 증명 분석을 수행하고, 
Volatility 3의 한계를 확인한 뒤 Volatility2 로 전환하여 
NTML 해시를 추출, 평문화한 메모리 포렌식 사례 분석 프로젝트

---

## 1. 프로젝트 개요 
**분석 목적**
해당 프로젝트는 [포트폴리오2: Windows 메모리 덤프 정상성 분석](https://github.com/hoongji/memory_forensics_process_analysis) 에서 사용한 동일한 메모리 덤프를 대상으로 진행한다.
시스템의 정상 여부 확인이 아닌 사용자 인증 정보가 메모리에 잔존하는지 여부를 검증하고, 이를 실제 문제로 연결하는 것을 목표로 한다.

구체적으로, 메모리 내 LSASS(Local Security Authority Subsystem Service) 프로세스를 중심으로 사용자의 계정 정보 및 NTML 해시 형태의 자격 증명 흔적을 추출하고, 외부 도구를 활용하여 이를 평문 비밀번호로 복구하는 과정을 수행하였다.

최종적으로는 
메모리 덤프의 사용자로 추정되는 John 계정의 비밀번호를 복구하는 것을 핵심 목표로 설정하였다. 

---

# 2. 분석 환경 및 데이터 출처
Host OS: Windows
분석 대상: Windows 7 SP1 x64

분석 도구: 
- Python 3.10.11
- python 2.17.18
- Volatility 2.6
- Volatility 3
- pypykatz
- hashcat 7.1.2
- John the Ripper 1.9.0
- Wordlist: rockyou.txt

---

# 3. 초기 환경
**3.1 OS 정보 확인**
windows.info 플러그인을 통해 대상 시스템이 Windows 7 계열 64bit 환경임을 확인

