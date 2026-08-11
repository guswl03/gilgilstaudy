#pragma once

#include "mac.h"
#include "ip.h"

// === 현재 인터페이스의 MAC 주소와 IPv4 주소를 읽어 공격자 자신의 정보를 채운다.
bool getAttackerInfo(const char* dev, Mac& mac, Ip& ip);
