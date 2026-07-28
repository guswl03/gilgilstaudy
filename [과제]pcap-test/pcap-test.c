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

void usage() {
	printf("syntax: pcap-test <interface>\nsample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
	char* dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap;
	struct pcap_pkthdr* header;
	const u_char* packet;
	int res;
	
	EthernetHeader* eth;
	Ipv4Header* ip;
	TcpHeader* tcp;
	
	int ip_hlen;
	int tcp_hlen;
	int all_header_len;
	int data_len;
	const u_char* data;
	int i;

	if (argc != 2) {
		usage();
		return -1;
	}

	dev = argv[1];

	if ((pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		exit(1);
	}

	while (1) {
		res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) {
			continue;
		} else if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		} else {
			eth = (EthernetHeader*)packet;

			if (ntohs(eth->type) == ETHER_TYPE_IP) {
				ip = (Ipv4Header*)(packet + sizeof(EthernetHeader));
				ip_hlen = (ip->version_ihl & 0x0f) * 4;

				if (ip->protocol == IP_PROTO_TCP) {
					tcp = (TcpHeader*)(packet + sizeof(EthernetHeader) + ip_hlen);
					tcp_hlen = (tcp->data_offset_reserved >> 4) * 4;

					all_header_len = sizeof(EthernetHeader) + ip_hlen + tcp_hlen;
					
					data_len = ntohs(ip->total_length) - ip_hlen - tcp_hlen;
					data = packet + all_header_len;

					printf("========================================\n");
					printf("packet length : %u\n", header->caplen);

					printf("src mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
						eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
						eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);

					printf("dst mac : %02X:%02X:%02X:%02X:%02X:%02X\n",
						eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
						eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5]);

					printf("src ip : %d.%d.%d.%d\n", ip->src_ip[0], ip->src_ip[1], ip->src_ip[2], ip->src_ip[3]);
					printf("dst ip : %d.%d.%d.%d\n", ip->dst_ip[0], ip->dst_ip[1], ip->dst_ip[2], ip->dst_ip[3]);

					printf("src port : %d\n", (int)ntohs(tcp->src_port));
					printf("dst port : %d\n", (int)ntohs(tcp->dst_port));

					printf("payload : ");
					for (i = 0; i < (data_len < MAX_PAYLOAD_PRINT ? data_len : MAX_PAYLOAD_PRINT); i++) {
						printf("%02X ", *(data + i));
					}
					printf("\n\n");
				}
			}
		}
	}

	pcap_close(pcap);
	return 0;
}
