#ifndef MAC_H
#define MAC_H
#include <cstdint>
#include <cstring>

class Mac{

public:
    Mac&operator =(uint8_t *op1);
    bool operator ==(uint8_t *op1);
    uint8_t val[6]; //mac addr
    void getMyMac(char *device);
    uint8_t* retnMac();
};


#endif // MAC_H
