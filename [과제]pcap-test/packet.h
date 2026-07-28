#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>

#pragma pack(push, 1)

typedef struct {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t type;
} EthernetHeader;

typedef struct {
	uint8_t version_ihl;
	uint8_t tos;
	uint16_t total_length;
	uint16_t identification;
	uint16_t fragment_offset;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t src_ip[4];
	uint8_t dst_ip[4];
} Ipv4Header;

typedef struct {
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t sequence;
	uint32_t acknowledgment;
	uint8_t data_offset_reserved;
	uint8_t flags;
	uint16_t window;
	uint16_t checksum;
	uint16_t urgent_pointer;
} TcpHeader;

#pragma pack(pop)

#endif
