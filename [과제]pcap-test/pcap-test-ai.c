#include <arpa/inet.h>
#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "packet.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

		// ethernet header
		if (header->caplen < sizeof(EthernetHeader)) continue;
		EthernetHeader* eth = (EthernetHeader*)packet;
		if (ntohs(eth->type) != 0x0800) continue;

		// ip header
		if (header->caplen < sizeof(EthernetHeader) + sizeof(Ipv4Header)) continue;
		Ipv4Header* ip = (Ipv4Header*)(packet + sizeof(EthernetHeader));
		int ip_hlen = (ip->version_ihl & 0x0f) * 4;
		if (ip_hlen < 20 || ip->protocol != 6) continue;

		// tcp header
		if (header->caplen < sizeof(EthernetHeader) + ip_hlen + sizeof(TcpHeader)) continue;
		TcpHeader* tcp = (TcpHeader*)(packet + sizeof(EthernetHeader) + ip_hlen);
		int tcp_hlen = (tcp->data_offset_reserved >> 4) * 4;
		if (tcp_hlen < 20) continue;

		int all_header_len = sizeof(EthernetHeader) + ip_hlen + tcp_hlen;
		if ((int)header->caplen < all_header_len) continue;

		int data_len = ntohs(ip->total_length) - ip_hlen - tcp_hlen;
		int captured_data_len = (int)header->caplen - all_header_len;
		if (data_len < 0) continue;
		if (data_len > captured_data_len) data_len = captured_data_len;
		const u_char* data = packet + all_header_len;

		printf("========================================\n");
		printf("packet length : %u\n", header->caplen);

		printf("src mac : ");
		for (int i = 0; i < 6; i++) {
			printf("%02X", eth->src_mac[i]);
			if (i != 5) printf(":");
		}
		printf("\n");

		printf("dst mac : ");
		for (int i = 0; i < 6; i++) {
			printf("%02X", eth->dst_mac[i]);
			if (i != 5) printf(":");
		}
		printf("\n");

		printf("src ip : %d.%d.%d.%d\n", ip->src_ip[0], ip->src_ip[1], ip->src_ip[2], ip->src_ip[3]);
		printf("dst ip : %d.%d.%d.%d\n", ip->dst_ip[0], ip->dst_ip[1], ip->dst_ip[2], ip->dst_ip[3]);
		printf("src port : %d\n", ntohs(tcp->src_port));
		printf("dst port : %d\n", ntohs(tcp->dst_port));

		printf("payload : ");
		int print_len = data_len;
		if (print_len > 20) print_len = 20;
		for (int i = 0; i < print_len; i++) printf("%02X ", data[i]);
		printf("\n\n");
	}

	pcap_close(pcap);
	return 0;
}
