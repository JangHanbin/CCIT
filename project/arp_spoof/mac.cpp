#include "mac.h"
#include <cstring>
#include <iostream>
#include <netinet/ether.h>
#include "getmyinfo.h"

Mac& Mac::operator=(uint8_t *op1)
{
    memcpy(this->val,op1,ETHER_ADDR_LEN);
    return *this;

}


bool Mac::operator==(uint8_t *op1)
{
    return (memcmp(this->val,op1,ETHER_ADDR_LEN)==0);

}
void Mac::getMyMac(char *device)
{
    getMyhaddr(device,this->val);
}

uint8_t* Mac::retnMac()
{
    return this->val;
}
