#pragma once

#include <arpa/inet.h>
#include "mac.h"

#pragma pack(push, 1)
// === 이더넷 프레임의 맨 앞 14바이트를 표현하는 구조체다.
struct EthHdr final {
	Mac dmac_;
	Mac smac_;
	uint16_t type_;

	Mac dmac() const { return dmac_; }
	Mac smac() const { return smac_; }
	uint16_t type() const { return ntohs(type_); }

	// === type 필드에서 자주 쓰는 프로토콜 번호 상수들이다.
	enum: uint16_t {
		Ip4 = 0x0800,
		Arp = 0x0806,
		Ip6 = 0x86DD
	};
};
typedef EthHdr *PEthHdr;
#pragma pack(pop)
