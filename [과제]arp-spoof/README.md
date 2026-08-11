# arp-spoof

ARP spoofing 과제를 위한 작업 폴더입니다. `send-arp` 과제를 바탕으로 sender/target MAC 조회, 감염 패킷 전송, 재감염 감지용 루프, IP packet relay 뼈대까지 포함했습니다.

## 요구 사항

- Linux
- g++
- libpcap-dev

## 실행

```bash
sudo ./arp-spoof <interface> <sender IP 1> <target IP 1> [<sender IP 2> <target IP 2> ...]
```

예시:

```bash
sudo ./arp-spoof eth0 172.30.1.17 172.30.1.254
```

## 구현 범위

- sender, target 쌍을 여러 개 받을 수 있도록 인자 파싱 및 세션 구조 구성
- sender, target MAC 조회
- sender/target 양방향 ARP infect 전송
- ARP recover 패킷 감지 시 재감염
- attacker가 받은 IPv4 packet relay 뼈대 구현
- 시간 관계상 실제 실행 환경에서 충분한 동작 검증은 아직 진행하지 못함

## 참고

- 과제 설명: https://gitlab.com/gilgil/sns/-/wikis/arp-spoofing/arp-spoofing
- 리포트 안내: https://gitlab.com/gilgil/sns/-/wikis/arp-spoofing/report-arp-spoof
