#include "ip.h"

#include <cstdio>

Ip::Ip(const std::string r) {
	// === "192.168.0.1" 같은 문자열을 32비트 정수 형태로 바꿔 저장한다.
	unsigned int a, b, c, d;
	int res = std::sscanf(r.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d);
	if (res != Size) {
		std::fprintf(stderr, "Ip::Ip sscanf return %d r=%s\n", res, r.c_str());
		return;
	}
	ip_ = (a << 24) | (b << 16) | (c << 8) | d;
}

Ip::operator std::string() const {
	// === 내부 정수 값을 다시 사람이 읽기 쉬운 dotted decimal 문자열로 바꾼다.
	char buf[32];
	std::sprintf(buf, "%u.%u.%u.%u",
		(ip_ & 0xFF000000) >> 24,
		(ip_ & 0x00FF0000) >> 16,
		(ip_ & 0x0000FF00) >> 8,
		(ip_ & 0x000000FF));
	return std::string(buf);
}
