#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "mac.h"
#include "ip.h"

#pragma pack(push, 1)
// === ARP 패킷의 고정 헤더와 주소 필드를 그대로 옮긴 구조체다.
struct ArpHdr final {
	uint16_t hrd_;
	uint16_t pro_;
	uint8_t hln_;
	uint8_t pln_;
	uint16_t op_;
	Mac smac_;
	Ip sip_;
	Mac tmac_;
	Ip tip_;

	uint16_t hrd() const { return ntohs(hrd_); }
	uint16_t pro() const { return ntohs(pro_); }
	uint8_t hln() const { return hln_; }
	uint8_t pln() const { return pln_; }
	uint16_t op() const { return ntohs(op_); }
	Mac smac() const { return smac_; }
	Ip sip() const { return ntohl(sip_); }
	Mac tmac() const { return tmac_; }
	Ip tip() const { return ntohl(tip_); }

	// === Ethernet 위에서 동작하는 ARP임을 나타낸다.
	enum: uint16_t {
		ETHER = 1
	};

	// === ARP 요청/응답 opcode 값이다.
	enum: uint16_t {
		Request = 1,
		Reply = 2
	};
};
typedef ArpHdr *PArpHdr;
#pragma pack(pop)
