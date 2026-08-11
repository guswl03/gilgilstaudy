#pragma once

#include <cstdint>
#include <cstring>
#include <string>

// === MAC 주소 6바이트를 비교/출력/초기화하기 쉽게 감싼 자료형이다.
struct Mac final {
	static constexpr int Size = 6;

	Mac() {}
	Mac(const Mac& r) { memcpy(this->mac_, r.mac_, Size); }
	Mac(const uint8_t* r) { memcpy(this->mac_, r, Size); }
	Mac(const std::string& r);

	Mac& operator = (const Mac& r) { memcpy(this->mac_, r.mac_, Size); return *this; }

	explicit operator uint8_t*() const { return const_cast<uint8_t*>(mac_); }
	explicit operator std::string() const;

	bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, Size) == 0; }
	bool operator != (const Mac& r) const { return memcmp(mac_, r.mac_, Size) != 0; }
	bool operator < (const Mac& r) const { return memcmp(mac_, r.mac_, Size) < 0; }
	bool operator > (const Mac& r) const { return memcmp(mac_, r.mac_, Size) > 0; }
	bool operator <= (const Mac& r) const { return memcmp(mac_, r.mac_, Size) <= 0; }
	bool operator >= (const Mac& r) const { return memcmp(mac_, r.mac_, Size) >= 0; }
	bool operator == (const uint8_t* r) const { return memcmp(mac_, r, Size) == 0; }

	void clear() { *this = nullMac(); }
	bool isNull() const { return *this == nullMac(); }
	bool isBroadcast() const { return *this == broadcastMac(); }
	bool isMulticast() const {
		return mac_[0] == 0x01 && mac_[1] == 0x00 && mac_[2] == 0x5E && (mac_[3] & 0x80) == 0x00;
	}

	// === 패킷 작성 시 자주 쓰는 특수 MAC 주소들을 제공한다.
	static Mac randomMac();
	static Mac& nullMac();
	static Mac& broadcastMac();

protected:
	uint8_t mac_[Size];
};

namespace std {
	template<>
	struct hash<Mac> {
		size_t operator() (const Mac& r) const {
			return std::_Hash_impl::hash(&r, Mac::Size);
		}
	};
}
