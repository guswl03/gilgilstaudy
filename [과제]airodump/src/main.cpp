#include "airodump/ap_table.hpp"
#include "airodump/packet_parser.hpp"

#include <pcap/pcap.h>

#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <iostream>

namespace {

volatile std::sig_atomic_t running = 1;

void stop_capture(int) {
    running = 0;
}

void print_usage(const char* program) {
    std::fprintf(stderr, "syntax : %s <interface>\n", program);
    std::fprintf(stderr, "sample : %s wlan0mon\n", program);
}

void render(const airodump::AccessPointTable& table) {
    std::cout << "\033[2J\033[H";
    std::cout << "BSSID              Beacons  ESSID\n";
    std::cout << "-----------------------------------------------\n";

    for (const airodump::AccessPoint& access_point : table.rows()) {
        std::printf(
            "%-17s  %7llu  %s\n",
            access_point.bssid.to_string().c_str(),
            static_cast<unsigned long long>(access_point.beacons),
            access_point.essid.c_str()
        );
    }
    std::cout << std::flush;
}

}  // namespace

int main(int argc, char* argv[]) {
    if (argc != 2) {
        print_usage(argv[0]);
        return 1;
    }

    char error_buffer[PCAP_ERRBUF_SIZE]{};
    pcap_t* capture = pcap_open_live(argv[1], 65535, 1, 100, error_buffer);
    if (capture == nullptr) {
        std::fprintf(
            stderr,
            "pcap_open_live(%s) failed: %s\n",
            argv[1],
            error_buffer
        );
        return 1;
    }

    if (pcap_datalink(capture) != DLT_IEEE802_11_RADIO) {
        std::fprintf(
            stderr,
            "%s is not providing Radiotap/802.11 packets. "
            "Put the wireless interface into monitor mode first.\n",
            argv[1]
        );
        pcap_close(capture);
        return 1;
    }

    std::signal(SIGINT, stop_capture);
    std::signal(SIGTERM, stop_capture);

    airodump::AccessPointTable table;
    auto next_render = std::chrono::steady_clock::now();
    bool screen_changed = true;

    while (running != 0) {
        pcap_pkthdr* header = nullptr;
        const u_char* packet = nullptr;
        const int result = pcap_next_ex(capture, &header, &packet);

        if (result == 1) {
            const auto observation = airodump::parse_beacon(
                reinterpret_cast<const std::uint8_t*>(packet),
                header->caplen
            );
            if (observation.has_value()) {
                table.update(*observation);
                screen_changed = true;
            }
        } else if (result == PCAP_ERROR_BREAK) {
            break;
        } else if (result == PCAP_ERROR) {
            std::fprintf(stderr, "pcap_next_ex failed: %s\n", pcap_geterr(capture));
            pcap_close(capture);
            return 1;
        }

        const auto now = std::chrono::steady_clock::now();
        if (screen_changed && now >= next_render) {
            render(table);
            screen_changed = false;
            next_render = now + std::chrono::milliseconds(500);
        }
    }

    render(table);
    pcap_close(capture);
    return 0;
}

