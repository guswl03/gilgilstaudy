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

bool getAttackerInfo(const char* dev, Mac& mac, Ip& ip) { //내정보
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return false;
    }

    struct ifreq ifr; //커널과 인터페이스 정보 주 받
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ - 1);

    //
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) { //맥주소 요청 ioctl명령
        perror("SIOCGIFHWADDR");
        close(sock);
        return false;
    }

    mac = Mac(
        reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data)
        );

    //
    if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
        perror("SIOCGIFADDR");
        close(sock);
        return false;
    }

    struct sockaddr_in* addr =
        reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);

    ip = Ip(ntohl(addr->sin_addr.s_addr));

    close(sock);
    return true;
}
