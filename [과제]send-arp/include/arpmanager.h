#pragma once

#include <pcap.h>
#include "mac.h"
#include "ip.h"

bool getSenderMac(
    pcap_t* pcap,
    const Mac& attackerMac,
    const Ip& attackerIp,
    const Ip& senderIp,
    Mac& senderMac
    );

bool sendInfectPacket(
    pcap_t* pcap,
    const Mac& attackerMac,
    const Mac& senderMac,
    const Ip& senderIp,
    const Ip& targetIp
    );