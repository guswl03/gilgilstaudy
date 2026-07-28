/*
 * 순서
 * 1. 네트워크 인터페이스 입력
 * 2. pcap_open_live로 패킷 캡처 시작
 * 3. Ethernet 헤더 확인
 * 4. IPv4 패킷인지 확인
 * 5. TCP 패킷인지 확인
 * 6. MAC / IP / Port / Payload 출력
 */

#include <arpa/inet.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "packet.h"

#define ETHER_TYPE_IP 0x0800
#define IP_PROTO_TCP 6
#define MAX_PAYLOAD_PRINT 20

//사용 방법
void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
	// pcap
	char* dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap;
	struct pcap_pkthdr* header;
	const u_char* packet;
	int res;

	// Ethernet, IPv4, TCP 헤더 포인터
	EthernetHeader* eth;
	Ipv4Header* ip;
	TcpHeader* tcp;

	// payload 길이 계산
	int ip_hlen;
	int tcp_hlen;
	int all_header_len;
	int data_len;
	const u_char* data;
	int i;

	// 하나
	if (argc != 2) {
		usage();
		return -1;
	}

	dev = argv[1];

	// 패킷 캡처
	if ((pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		exit(1);
	}

	while (1) {
		// 하나씩
		res = pcap_next_ex(pcap, &header, &packet);

		// timeout 기다림
		if (res == 0) {
			continue;
		}
		// 오류 -  ai
		else if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		else {
			// 시작 위치
			eth = (EthernetHeader*)packet;

			// 0x0800
			if (ntohs(eth->type) == ETHER_TYPE_IP) {
				// Ethernet 헤더 다음 위치가 IPv4 헤더의 시작 위치 - ai
				ip = (Ipv4Header*)(packet + sizeof(EthernetHeader));

				// IHL 값은 4바이트 단위이므로 4를 곱함 - ai
				ip_hlen = (ip->version_ihl & 0x0f) * 4;

				// 프로토콜 번호 6
				if (ip->protocol == IP_PROTO_TCP) {
					// Ethernet 헤더와 IP 헤더 다음 위치가 TCP 헤더 - ai
					tcp = (TcpHeader*)
						(packet + sizeof(EthernetHeader) + ip_hlen);

					// 4
					tcp_hlen =
						(tcp->data_offset_reserved >> 4) * 4;

					// 전체 길이
					all_header_len =
						sizeof(EthernetHeader) +
						ip_hlen +
						tcp_hlen;

					// IP 전체 길이에서 IP/TCP 헤더를 빼서 payload 길이 계산 - ai
					data_len =
						ntohs(ip->total_length) -
						ip_hlen -
						tcp_hlen;

					data = packet + all_header_len;

					printf("========================================\n");
					printf("packet length : %u\n", header->caplen);

					// 첫 MAC
					printf(
						"src mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
						eth->src_mac[0], eth->src_mac[1],
						eth->src_mac[2], eth->src_mac[3],
						eth->src_mac[4], eth->src_mac[5]
					);

					// 마 MAC
					printf(
						"dst mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
						eth->dst_mac[0], eth->dst_mac[1],
						eth->dst_mac[2], eth->dst_mac[3],
						eth->dst_mac[4], eth->dst_mac[5]
					);

					// 첫 ~ 마 IPv4
					printf(
						"src ip : %d.%d.%d.%d\n",
						ip->src_ip[0], ip->src_ip[1],
						ip->src_ip[2], ip->src_ip[3]
					);

					printf(
						"dst ip : %d.%d.%d.%d\n",
						ip->dst_ip[0], ip->dst_ip[1],
						ip->dst_ip[2], ip->dst_ip[3]
					);

					// 호스트 순서 변환
					printf(
						"src port : %d\n",
						(int)ntohs(tcp->src_port)
					);

					printf(
						"dst port : %d\n",
						(int)ntohs(tcp->dst_port)
					);

					// Payload 16진수
					printf("payload : ");

					for (
						i = 0;
						i < (
							data_len < MAX_PAYLOAD_PRINT
							? data_len
							: MAX_PAYLOAD_PRINT
						);
						i++
					) {
						printf("%02X ", *(data + i));
					}

					printf("\n\n");
				}
			}
		}
	}

	pcap_close(pcap);
	//return 0;
}
