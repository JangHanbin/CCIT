#include "ip.h"
#include <cstring>
#include <iostream>



Ip& Ip::operator=(uint8_t *op1)
{
    memcpy(this->val,op1,IP_ADDR_LEN);
    return *this;

}

Ip& Ip::operator=(uint32_t *op1)
{
    memcpy(this->val,op1,IP_ADDR_LEN);
    return *this;

}



bool Ip::operator==(uint8_t *op1)
{
    return (memcmp(this->val,op1,IP_ADDR_LEN)==0);

}

IpPacket::IpPacket(const u_char *packet)
{
    this->eh=(struct ether_header*)packet;
    if(ntohs(eh->ether_type)==ETHERTYPE_IP)
    {
        this->isIpPacket=true;
        this->iph=(struct iphdr*)(packet+sizeof(struct ether_header));
        this->daddr=&this->iph->daddr;
        this->saddr=&this->iph->saddr;

    }
    else
        this->isIpPacket=false;
}

