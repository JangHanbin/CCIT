#ifndef IP_H
#define IP_H

#include <cstdint>
#include <cstring>

#define IP_ADDR_LEN 4

class Ip{

public:
    Ip& operator =(uint8_t *op1);
    bool operator ==(uint8_t *op1);
    uint8_t val[IP_ADDR_LEN]; //IP

};


#endif // IP_H
