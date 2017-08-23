#include "mac.h"
#include <cstring>
#include <string>

Mac::Mac()
{

}

Mac& Mac::operator=(char *addr)
{
    memcpy(this->macAddr,addr,6);

    return *this;

}


Mac& Mac::operator=(uint8_t *addr)
{
    memcpy(this->macAddr,addr,6);

    return *this;

}


Mac& Mac::operator=(Mac &other)
{
    memcpy(this->macAddr,other.macAddr,6);

    return *this;

}
