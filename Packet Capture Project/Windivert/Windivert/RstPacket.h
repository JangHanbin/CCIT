#pragma once

#include "windivert.h"
#include <iostream>

class RstPacket
{
	WINDIVERT_IPHDR ip;
	WINDIVERT_TCPHDR tcp;
public:
	RstPacket(uint8_t* packet);
	void makeRSTPacket(uint8_t* packet);
};

