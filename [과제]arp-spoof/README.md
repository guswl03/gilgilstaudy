# arp-spoof

ARP spoofing 과제를 위한 작업 폴더입니다.

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

## 진행 메모

- sender, target 쌍을 여러 개 받을 수 있도록 구현 예정
- ARP infect 유지 및 복구 감지 후 재감염 로직 구현 예정
- sender가 보낸 IP packet relay 로직 구현 예정
- 시간 관계상 실제 실행 환경에서 충분한 동작 검증은 아직 진행하지 못함

## 참고

- 과제 설명: https://gitlab.com/gilgil/sns/-/wikis/arp-spoofing/arp-spoofing
- 리포트 안내: https://gitlab.com/gilgil/sns/-/wikis/arp-spoofing/report-arp-spoof
