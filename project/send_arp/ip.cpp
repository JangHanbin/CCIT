#include "ip.h"
#include <cstring>
#include <iostream>



Ip& Ip::operator=(uint8_t *op1)
{
    memcpy(this->val,op1,IP_ADDR_LEN);
    return *this;

}


bool Ip::operator==(uint8_t *op1)
{
    return (memcmp(this->val,op1,IP_ADDR_LEN)==0);

}
