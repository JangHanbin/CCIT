#ifndef IP_H
#define IP_H

#include <cstdint>
#include <cstring>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include "mac.h"

#define IP_ADDR_LEN 4

class Ip{

public:
    Ip& operator =(uint8_t *op1);
    bool operator ==(uint8_t *op1);
    bool operator ==(uint32_t *op1);
    Ip& operator=(uint32_t *op1);
    Ip& operator =(char* op1);
    uint32_t val; //IP
    void getMyIp(char* device);
    uint32_t* retnIP();

};
#endif // IP_H
