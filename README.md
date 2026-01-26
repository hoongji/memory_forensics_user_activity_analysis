# Memory Forensics: User Credential Recovery from Windows 7 Memory Dump

 Windows 7 메모리 덤프에서 사용자(john)의 비밀번호를 복구하기 위해 
lsass.exe 기반 자격 증명 분석을 수행하고, 
Volatility 3의 한계를 확인한 뒤 Volatility2 로 전환하여 
NTML 해시를 추출, 평문화한 메모리 포렌식 사례 분석 프로젝트



## 1. 프로젝트 개요 
**분석 목적**
해당 프로젝트는 [포트폴리오2: Windows 메모리 덤프 정상성 분석](https://github.com/hoongji/memory_forensics_process_analysis) 에서 사용한 동일한 메모리 덤프를 대상으로 진행한다.
시스템의 정상 여부 확인이 아닌 사용자 인증 정보가 메모리에 잔존하는지 여부를 검증하고, 이를 실제 문제로 연결하는 것을 목표로 한다.

구체적으로, 메모리 내 LSASS(Local Security Authority Subsystem Service) 프로세스를 중심으로 사용자의 계정 정보 및 NTML 해시 형태의 자격 증명 흔적을 추출하고, 외부 도구를 활용하여 이를 평문 비밀번호로 복구하는 과정을 수행하였다.

최종적으로는 
메모리 덤프의 사용자로 추정되는 John 계정의 비밀번호를 복구하는 것을 핵심 목표로 설정하였다. 



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


### 데이터 출처

- 메모리 덤프 출처: TryHackMe – Memory Forensics 실습 과제
- 제공 형태: Windows 메모리 덤프 (VMEM)
- 시나리오: 가상의 사용자(John) 환경에서 수집된 메모리 덤프
- 목적: 디지털 포렌식 분석 흐름 학습 및 사용자 행위 분석 연습 (해당 덤프는 교육 목적의 공개 자료)
- 참고 링크: [https://tryhackme.com/](https://tryhackme.com/room/memoryforensics)



# 3. 초기 환경
**3.1 OS 정보 확인** 

![windows.info 결과](screenshots/windows.info)

windows.info 플러그인을 통해 대상 시스템이 Windows 7 계열 64bit 환경임을 확인함.
Kernel Base 주소가 정상적으로 식별되었고 이후 프로세스 및 인증 정보 분석이 가능한 상태로 판단된다.


# 4 분석 접근 전략 

- 해당 프로젝트는 악성 행위 탐지보다는 **사용자 인증 정보가 메모리에 잔존할 가능성**에 초첨을 맞춘다.
  
- **본 분석에서는 다음 질문을 중심으로 접근한다 :**
  1. 실제로 John 이라는 사용자가 존재하는가?
  2. 인증을 담당하는 핵심 프로세스가 정상 상태인가?
  3. 자격 증명 정보 분석이 가능한 메모리 구조인가?


 # 5 사용자 존재 여부 및 인증 프로세스 검증

 ### 5.1 사용자 계정 직접 확인 시도
 - Volatilit 2의 **windows.users** 플러그인을 통해 사용자 확인을 시도했다.
 - 프로젝트 분석시 먼저 사용한 Volatility 3 버전에서는 제거된 플러그인 이었기에 직접적인 사용자 목록은 확인이이 불가하였다.
 - 대신 인증 프름을 담당하는 프로세스를 기준으로 간접 검증 전략으로 변경하였다.


### 5.2 lsass.exe 프로세스 확인 
*lsass.exe는 Windows에서 인증,계정,해시 처리를 담당하는 핵심 프로세스이므로 사용자 비밀번호, NTLM 해시, Kerberos 티켓 등은 **로그인 이후 lsass 메모리에 잔존 가능성**이 있다고 판단하여 lsass.exe 프로세스를 확인하고자 하였다.*

![windows.pslist 결과](screenshots/windows.pslist) 
lsass.exe (PID 496) 이 정상적인 경로로 실행됨을 확인하였다. 

![windows.cmdline 결과](screenshots/windows.cmdline) 
실행 경로가 C:\Windows\System32\lsass.exe 임을 확인하였다. 

정상 경로와 정상 PID 이므로 위장 프로세스 가능성이 낮다고 판단하였다. 


### 5.3 메모리 점유 여부 확인 
![windows.memmap --pid 496](screenshots/memmap1)
![windows.memmap 결과](screenshots/memmap2)
windows.memmap 플러그인을 통해 pid 496(lsass.exe)가 다수의 가상 메모리 영역을 실제로 점유 중임을 확인하였다. 
출력이 수십줄이 나와 프로세스가 정상적으로 메모리에 되었음을 확인하였다. (덤프 대상이 존재함)
이를 통해 해당 프로세스의 메모리 덤프가 가능하다고 판단하고, 자격 증명 정보 분석을 위해 메모리 덤프를 진행하였다. 


# 6 lsass.exe 메모리 덤프 및 한계
### 6.1 메모리 덤프 
![windows.dumpfiles --pid 496](screenshots/dumpfiles)
pid 496(lsass.exe)가 사용하던 메모리 영역 파일로 매핑된 영역(imageSectionObject)을 개별 파일로 덤프했다. 

![lsass.exe의 이미지 경로 확인. ImageSectionObject.lsass.exe.img](screenshots/dumpfiles_lsass.exe)


windows.dumpdfiles 플러그인을 사용하여 lsass.exe(PID 496) 프로세스의 메모리 영역을 덤프하였다. 
덤프 결과, lsass.exe 본체와 함께 인증 관련 DLL(msv1_0.dll,kerberos.dll, wdigest.dll, samsrv.dll 등)이 추출되었으며, 이는 lsass 프로세스가 정상적으로 인증 모듈을 로드하고 있었음을 의미한다. 
이 중 lsass.exe 메모리 이미지를 대상으로 자격 증명 분석을 진행하였다. 

*생성된 파일 중 ImageSectionObject.lsass.exe.img 경로를 확인한다. (mimikatz or pypykatz 사용)*


### 6.2 자격 증명 추출 시도
![pypykatz 추출 실패](screenshots/pypykatz)

pypykatz 실행 시 위와 같은 오류가 반복적으로 발생했다. 
*python -m pypykatz* , *pypykatz lsa minidump <dumpfile>* , *패키지 재설치(pip uninstall / reinstall)* , *명령어 변경 및 강제 실행*을 시도하였으나 모두 동일한 오류가 발생되었다. 이로 인해 lsass 덤프 분석 단계 이전에 pypykatz 도구가 Python 실행 단계에서 정상적으로 구동되지 않았다는 사실을 알 수 있었다. 

python 패키지는 정상적으로 설치된 상태였으나, Pyhton 모듈 실행 방식(-m)과 exe 래퍼 방식 모두 실패하였다. 
lsass 메모리 내 인증정보의 존재 여부와는 무관하게 도구 실행 구조상의 한계로 판단하였다. 

한편 Voltatility3 의 **windows.dumpfiles** 플러그인은 **ImageSectionObject**에 매핑된 메모리영역을 중심으로 덤프를 수행하므로, ㅣlsasss 프로세스의 heap 또는 private memory 영역이 포함되지 않았을 경우도 함께 고려하면 사용자 인증정보 영역이 포함되어 있지 않거나 분리되어 있을 가능성도 함께 고려해야했다. 
이를 통해 본 덤프 파일만으로는 자격 증명 추출이 제한될 수 있다는 판단을 내렸다. 

**이와 같은 제약으로 인해, 해당 실습에서는 사용자 정보 추출에 대해 Volatility2 사용을 권장한 실습 가이드의 방향에 따라 분석 도구를 Volatility2 로 전환하여 진행하기로 하였다.**


# 7 Volatility2 전환 및 검증
### 7.1 프로파일 사전 검증 과정(imageinfo)
![volatility2 imageinfo](screenshots/vol2.6_imageinfo)

메모리 덤프의 운영체제 버전과 커널 구조를 추정하기 위해 Volatility2의 imageinfo 플러그인을 실행하였다. 

분석 결과, 여러 개의 예상 프로파일이 제시되었으며 이 중 **Win7SP1x64**를 사용하기로 결정했다. 

*해당 프로파일을 선택한 이유는 TryHackMe Windows 메모리 분석 문제에서 가장 빈번하게 사용되며, 공식 walkthrough에서도 주로 채택되는 프로파일이기 때문에 선택하였다.*

### 7.2 프로세스 구조 검증(pslist)
![volatility2 pslist](screenshots/vol2.6_pslist)

선택한 프로파일이 실제로 적절한지 확인하기 위해
**profile=Win7SP1x64 pslist** 플러그인을 실행하였다.

이 단계에서는 다음 두 자기를 중점적으로 확인하였다.

1. lsass.exe 프로세스의 존재 여부
2. 시스템 프로세스 트리가 정상적으로 파싱되는지 여부
   
lsass.exe 존재여부를 확인하고 pid , 시스템이 정상적으로 파싱되는지를 확인해보기로 했다. 
lsass.exe가 정상적인 부모 프로세스(wininit.exe) 하위에서 실행되고 있음을 확인함으로써, 해당 메모리 덤프는 자격증명 분석을 수행하기에 메모리 구조가 정상적으로 파싱되었음을 판단하였다. 

*시스템이 정상적으로 파싱되는지 = 메모리 덤프에서 커널 구조(KDBG)가 정상적으로 식별되었고, 프로세스 리스트가 일관된 구조로 파싱되고 있음을 의미*


### 7.3 NTLM 해시 추출(hashdump)
![volatility2 hashdump](screenshots/vol2.6_hashdump)

자격 증명 정보를 확보하기 위해
Volatility2의 hashdump 플러그인을 실행하여 사용자의 비밀번호를 파악하고자 하였다. 
volatiliy3가 아닌 volatility2를 이용해서 해당 메모리 덤프를 분석하라는 권유가 있는 이유는 volatility2가 정확도 보다 획득 가능성을 우선한 방식이라 그런것같다. 안정성을 이유로 volatility3에서는 제거가 된 플러그인이다. 해당 단계에서 john의 비밀번호가 나오는데 NTML 해시 문자열이 나온다. 

### 7.4 비밀번호 평문화 과정(hashcat)

안됨.. 

### 7.5 john the ripper 사용
