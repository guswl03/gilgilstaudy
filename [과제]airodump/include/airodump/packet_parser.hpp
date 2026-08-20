#ifndef AIRODUMP_PACKET_PARSER_HPP
#define AIRODUMP_PACKET_PARSER_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>

namespace airodump {

struct MacAddress {
    std::array<std::uint8_t, 6> bytes{};

    bool operator<(const MacAddress& other) const noexcept;
    bool operator==(const MacAddress& other) const noexcept;
    std::string to_string() const;
};

struct BeaconObservation {
    MacAddress bssid;
    std::string essid;
};

// Parses one packet captured with the DLT_IEEE802_11_RADIO link type.
// Returns an observation only when the packet is a complete 802.11 Beacon.
std::optional<BeaconObservation> parse_beacon(
    const std::uint8_t* packet,
    std::size_t captured_length
);

}  // namespace airodump

#endif  // AIRODUMP_PACKET_PARSER_HPP

