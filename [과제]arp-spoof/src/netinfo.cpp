#include "netinfo.h"

#include <cstdio>
#include <cstring>
#include <cstdint>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

bool getAttackerInfo(const char* dev, Mac& mac, Ip& ip) {
    // === ioctl을 쓰기 위한 소켓을 하나 연다. 실제 통신용이라기보다 인터페이스 정보 조회용이다.
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr;
    std::memset(&ifr, 0, sizeof(ifr));
    std::strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    // === SIOCGIFHWADDR로 인터페이스의 MAC 주소를 읽는다.
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("SIOCGIFHWADDR");
        close(sock);
        return false;
    }

    mac = Mac(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));

    // === SIOCGIFADDR로 인터페이스의 IPv4 주소를 읽는다.
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("SIOCGIFADDR");
        close(sock);
        return false;
    }

    struct sockaddr_in* addr = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);

    // === 네트워크 바이트 순서를 host 바이트 순서로 바꿔 Ip 객체에 저장한다.
    ip = Ip(ntohl(addr->sin_addr.s_addr));

    close(sock);
    return true;
}
