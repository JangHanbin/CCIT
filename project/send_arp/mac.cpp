#include "mac.h"
#include <cstring>
#include <iostream>
#include <netinet/ether.h>

Mac& Mac::operator=(uint8_t *op1)
{
    memcpy(this->val,op1,ETHER_ADDR_LEN);
    return *this;

}


bool Mac::operator==(uint8_t *op1)
{
    return (memcmp(this->val,op1,ETHER_ADDR_LEN)==0);

}
