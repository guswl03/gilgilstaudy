#include "airodump/ap_table.hpp"

namespace airodump {

void AccessPointTable::update(const BeaconObservation& observation) {
    auto [iterator, inserted] = access_points_.try_emplace(
        observation.bssid,
        AccessPoint{observation.bssid, 0, observation.essid}
    );

    AccessPoint& access_point = iterator->second;
    ++access_point.beacons;

    const bool new_essid_is_known =
        observation.essid != "<unknown>" && observation.essid != "<hidden>";
    if (inserted || new_essid_is_known || access_point.essid == "<unknown>") {
        access_point.essid = observation.essid;
    }
}

std::vector<AccessPoint> AccessPointTable::rows() const {
    std::vector<AccessPoint> result;
    result.reserve(access_points_.size());
    for (const auto& [bssid, access_point] : access_points_) {
        static_cast<void>(bssid);
        result.push_back(access_point);
    }
    return result;
}

std::size_t AccessPointTable::size() const noexcept {
    return access_points_.size();
}

}  // namespace airodump
