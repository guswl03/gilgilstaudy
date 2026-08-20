#include "airodump/packet_parser.hpp"

#include <algorithm>
#include <cstdio>

namespace airodump {
namespace {

constexpr std::size_t kRadiotapMinimumLength = 8;
constexpr std::size_t kDot11ManagementHeaderLength = 24;
constexpr std::size_t kBeaconFixedParametersLength = 12;
constexpr std::size_t kMaximumSsidLength = 32;

constexpr std::uint8_t kManagementFrameType = 0;
constexpr std::uint8_t kBeaconFrameSubtype = 8;
constexpr std::uint8_t kSsidElementId = 0;

std::uint16_t read_little_endian_u16(const std::uint8_t* value) noexcept {
    return static_cast<std::uint16_t>(value[0]) |
           static_cast<std::uint16_t>(value[1] << 8U);
}

std::string display_essid(const std::uint8_t* value, std::size_t length) {
    if (length == 0 ||
        std::all_of(value, value + length, [](std::uint8_t byte) { return byte == 0; })) {
        return "<hidden>";
    }

    std::string result;
    result.reserve(length);
    char escaped[5]{};

    for (std::size_t index = 0; index < length; ++index) {
        const std::uint8_t byte = value[index];
        if (byte >= 0x20 && byte != 0x7f) {
            result.push_back(static_cast<char>(byte));
            continue;
        }

        std::snprintf(escaped, sizeof(escaped), "\\x%02X", byte);
        result.append(escaped);
    }

    return result;
}

}  // namespace

bool MacAddress::operator<(const MacAddress& other) const noexcept {
    return bytes < other.bytes;
}

bool MacAddress::operator==(const MacAddress& other) const noexcept {
    return bytes == other.bytes;
}

std::string MacAddress::to_string() const {
    char buffer[18]{};
    std::snprintf(
        buffer,
        sizeof(buffer),
        "%02X:%02X:%02X:%02X:%02X:%02X",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5]
    );
    return buffer;
}

std::optional<BeaconObservation> parse_beacon(
    const std::uint8_t* packet,
    std::size_t captured_length
) {
    if (packet == nullptr || captured_length < kRadiotapMinimumLength) {
        return std::nullopt;
    }

    if (packet[0] != 0) {
        return std::nullopt;
    }

    const std::size_t radiotap_length = read_little_endian_u16(packet + 2);
    if (radiotap_length < kRadiotapMinimumLength ||
        radiotap_length > captured_length) {
        return std::nullopt;
    }

    const std::size_t minimum_beacon_length =
        radiotap_length +
        kDot11ManagementHeaderLength +
        kBeaconFixedParametersLength;
    if (captured_length < minimum_beacon_length) {
        return std::nullopt;
    }

    const std::uint8_t* dot11 = packet + radiotap_length;
    const std::uint16_t frame_control = read_little_endian_u16(dot11);
    const std::uint8_t protocol_version = frame_control & 0x03U;
    const std::uint8_t frame_type = (frame_control >> 2U) & 0x03U;
    const std::uint8_t frame_subtype = (frame_control >> 4U) & 0x0fU;

    if (protocol_version != 0 ||
        frame_type != kManagementFrameType ||
        frame_subtype != kBeaconFrameSubtype) {
        return std::nullopt;
    }

    BeaconObservation observation;
    std::copy_n(dot11 + 16, observation.bssid.bytes.size(), observation.bssid.bytes.begin());
    observation.essid = "<unknown>";

    std::size_t position = minimum_beacon_length;
    while (position < captured_length) {
        if (captured_length - position < 2) {
            return std::nullopt;
        }

        const std::uint8_t element_id = packet[position];
        const std::size_t element_length = packet[position + 1];
        position += 2;

        if (element_length > captured_length - position) {
            return std::nullopt;
        }

        if (element_id == kSsidElementId) {
            if (element_length > kMaximumSsidLength) {
                return std::nullopt;
            }
            observation.essid = display_essid(packet + position, element_length);
            return observation;
        }

        position += element_length;
    }

    return observation;
}

}  // namespace airodump

