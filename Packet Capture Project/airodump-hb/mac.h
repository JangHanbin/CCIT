#ifndef MAC_H
#define MAC_H

#include <cstring>
#include <iostream>

class Mac
{

public:
    uint8_t macAddr[6];

    Mac();
    Mac& operator=(char *addr);
    Mac& operator=(uint8_t *addr);
    Mac& operator=(Mac &other);


};

#endif // MAC_H
