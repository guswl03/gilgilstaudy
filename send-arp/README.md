```
# send-arp

ARP spoofing을 수행하는 프로그램입니다.

## Build

```bash
cd src
make

## Usage

```bash
sudo ./send-arp <interface> <sender IP> <target IP>
```

실행 예시:

```bash
sudo ./send-arp eth0 172.30.1.17 172.30.1.254
```

## Demo

### Attacker

![](attacker.mp4)

### Target

![](target.mp4)
