#ifndef CALCHECKSUM_H
#define CALCHECKSUM_H
#include <iostream>

u_int16_t calTCPChecksum(uint8_t* data, int dataLen);
uint16_t calIPChecksum(uint8_t* data);
#endif // CALCHECKSUM_H
