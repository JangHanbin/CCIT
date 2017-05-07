#include "ip.h"

#include <cstring>
#include <iostream>
#include <arpa/inet.h>
#include "getmyinfo.h"

Ip& Ip::operator=(uint8_t *op1)
{
    memcpy(&this->val,op1,IP_ADDR_LEN);
    return *this;

}

Ip& Ip::operator=(uint32_t *op1)
{
    memcpy(&this->val,op1,IP_ADDR_LEN);
    return *this;

}


Ip& Ip::operator=(char* op1)
{
    inet_pton(AF_INET,op1,&this->val);
    return *this;

}


bool Ip::operator==(uint8_t *op1)
{
    return (memcmp(&this->val,op1,IP_ADDR_LEN)==0);

}

bool Ip::operator==(uint32_t *op1)
{
    return (memcmp(&this->val,op1,IP_ADDR_LEN)==0);

}

void Ip::getMyIp(char *device)
{
    getMyIP(device,&this->val);
}

uint32_t* Ip::retnIP()
{
    return &this->val;
}
