#include "mac.h"

#include <cstdio>
#include <cstdlib>

Mac::Mac(const std::string& r) {
	// === "aa:bb:cc:dd:ee:ff" 같은 문자열에서 16진수만 뽑아 6바이트로 저장한다.
	std::string s;
	for (char ch : r) {
		if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f'))
			s += ch;
	}
	int res = std::sscanf(s.c_str(), "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
		&mac_[0], &mac_[1], &mac_[2], &mac_[3], &mac_[4], &mac_[5]);
	if (res != Size) {
		std::fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
		return;
	}
}

Mac::operator std::string() const {
	// === 내부 6바이트 배열을 사람이 읽는 MAC 문자열 형태로 바꾼다.
	char buf[20];
	std::sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
		mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
	return std::string(buf);
}

Mac Mac::randomMac() {
	// === 테스트 용도로 임의 MAC을 만들되 멀티캐스트 비트는 끈다.
	Mac res;
	for (int i = 0; i < Size; i++)
		res.mac_[i] = uint8_t(std::rand() % 256);
	res.mac_[0] &= 0x7F;
	return res;
}

Mac& Mac::nullMac() {
	// === ARP request의 target MAC처럼 "아직 모름"을 표현할 때 쓰는 00:00:00:00:00:00이다.
	static uint8_t value[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	static Mac res(value);
	return res;
}

Mac& Mac::broadcastMac() {
	// === 모든 호스트에게 보내는 브로드캐스트 MAC 주소다.
	static uint8_t value[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	static Mac res(value);
	return res;
}
