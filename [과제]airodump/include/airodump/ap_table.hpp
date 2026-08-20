#ifndef AIRODUMP_AP_TABLE_HPP
#define AIRODUMP_AP_TABLE_HPP

#include "airodump/packet_parser.hpp"

#include <cstdint>
#include <map>
#include <vector>

namespace airodump {

struct AccessPoint {
    MacAddress bssid;
    std::uint64_t beacons{0};
    std::string essid{"<unknown>"};
};

class AccessPointTable {
public:
    void update(const BeaconObservation& observation);
    std::vector<AccessPoint> rows() const;
    std::size_t size() const noexcept;

private:
    std::map<MacAddress, AccessPoint> access_points_;
};

}  // namespace airodump

#endif  // AIRODUMP_AP_TABLE_HPP

