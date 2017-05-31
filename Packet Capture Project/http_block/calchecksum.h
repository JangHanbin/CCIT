#ifndef CALCHECKSUM_H
#define CALCHECKSUM_H
#include <iostream>

u_int16_t calTCPChecksum(uint8_t* data, int dataLen);   // need to data pointer at IP Header
uint16_t calIPChecksum(uint8_t* data);                  // need to data pointer at IP Header
#endif // CALCHECKSUM_H
