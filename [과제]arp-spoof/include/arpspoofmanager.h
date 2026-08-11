#pragma once

#include <pcap.h>
#include <vector>
#include "mac.h"
#include "ip.h"

struct SpoofSession {
    Ip senderIp;
    Mac senderMac;
    Ip targetIp;
    Mac targetMac;
};

class ArpSpoofManager {
public:
    ArpSpoofManager(pcap_t* pcap, const Mac& attackerMac, const Ip& attackerIp);

    bool resolveMac(const Ip& ip, Mac& mac) const;
    bool initializeSession(SpoofSession& session) const;
    bool infectSender(const SpoofSession& session) const;
    bool infectTarget(const SpoofSession& session) const;
    bool infect(const SpoofSession& session) const;
    bool infectAll(const std::vector<SpoofSession>& sessions) const;
    void relayLoop(const std::vector<SpoofSession>& sessions) const;

private:
    bool sendArpRequest(const Ip& ip) const;
    bool sendArpReply(const Mac& receiverMac, const Ip& receiverIp, const Ip& claimedIp) const;
    bool relayPacket(const u_char* packet, uint32_t length, const Mac& dstMac) const;
    bool matchesRecoverPacket(const SpoofSession& session, const u_char* packet, uint32_t length) const;
    const SpoofSession* findSessionBySender(const std::vector<SpoofSession>& sessions, const Mac& srcMac, const Mac& dstMac) const;

    pcap_t* pcap_;
    Mac attackerMac_;
    Ip attackerIp_;
};
