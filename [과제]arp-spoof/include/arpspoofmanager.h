#pragma once

#include <pcap.h>
#include <vector>
#include "mac.h"
#include "ip.h"

// === 한 개의 sender <-> target 흐름을 추적하기 위한 정보 묶음이다.
struct SpoofSession {
    Ip senderIp;
    Mac senderMac;
    Ip targetIp;
    Mac targetMac;
};

class ArpSpoofManager {
public:
    // === 공격자 정보와 pcap 핸들을 받아 전체 스푸핑 작업을 관리한다.
    ArpSpoofManager(pcap_t* pcap, const Mac& attackerMac, const Ip& attackerIp);

    // === IP로 ARP 질의를 보내 실제 MAC 주소를 알아낸다.
    bool resolveMac(const Ip& ip, Mac& mac) const;

    // === sender와 target 두 호스트의 MAC 주소를 모두 채워 세션을 완성한다.
    bool initializeSession(SpoofSession& session) const;

    // === sender에게 "target IP는 내 MAC이야"라고 속이는 ARP reply를 보낸다.
    bool infectSender(const SpoofSession& session) const;

    // === target에게 "sender IP는 내 MAC이야"라고 속이는 ARP reply를 보낸다.
    bool infectTarget(const SpoofSession& session) const;

    // === 한 세션의 양쪽을 동시에 감염시킨다.
    bool infect(const SpoofSession& session) const;
    bool infectAll(const std::vector<SpoofSession>& sessions) const;

    // === 감염 후에는 패킷을 계속 받으면서 복구 시도를 막고 트래픽을 릴레이한다.
    void relayLoop(const std::vector<SpoofSession>& sessions) const;

private:
    // === 특정 IP의 MAC 주소를 묻는 ARP request를 브로드캐스트한다.
    bool sendArpRequest(const Ip& ip) const;

    // === receiver에게 claimedIp가 공격자 MAC이라고 속이는 ARP reply를 만든다.
    bool sendArpReply(const Mac& receiverMac, const Ip& receiverIp, const Ip& claimedIp) const;

    // === 가로챈 이더넷 프레임의 MAC 주소만 바꿔 목적지로 다시 보낸다.
    bool relayPacket(const u_char* packet, uint32_t length, const Mac& dstMac) const;

    // === 정상 ARP를 다시 보내며 감염을 풀려는 패킷인지 검사한다.
    bool matchesRecoverPacket(const SpoofSession& session, const u_char* packet, uint32_t length) const;

    // === 현재 캡처한 프레임이 어떤 세션의 sender/target에서 온 것인지 찾는다.
    const SpoofSession* findSessionBySender(const std::vector<SpoofSession>& sessions, const Mac& srcMac, const Mac& dstMac) const;

    pcap_t* pcap_;
    Mac attackerMac_;
    Ip attackerIp_;
};
