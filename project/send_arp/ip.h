#ifndef IP_H
#define IP_H

#include <cstdint>
#include <cstring>
#include <netinet/ether.h>
#include <netinet/ip.h>

#define IP_ADDR_LEN 4

class Ip{

public:
    Ip& operator =(uint8_t *op1);
    bool operator ==(uint8_t *op1);
    Ip& operator=(uint32_t *op1);
    uint8_t val[IP_ADDR_LEN]; //IP

};

class IpPacket{
public :
    struct ether_header* eh;
    struct iphdr* iph;
    bool isIpPacket;
    Ip daddr;
    Ip saddr;
    IpPacket(const u_char* packet);
};

#endif // IP_H
