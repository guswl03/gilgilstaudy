#include <cstdio>

void usage() {
    std::printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
    std::printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || ((argc - 2) % 2) != 0) {
        usage();
        return 1;
    }

    std::printf("arp-spoof scaffold is ready.\n");
    std::printf("interface: %s\n", argv[1]);
    return 0;
}
