#ifndef APINFO_H
#define APINFO_H

#include <iostream>
#include "mac.h"

class APInfo
{

    uint32_t beacons{0};
    uint32_t data{0};
    uint8_t channel;
    uint8_t MB; //Maximum speed supported by AP if QOS service enabled added alpha 'e'

public:
    Mac BSSID;
    char enc[4];
    char cipher[6];
    char auth[4];
    char ESSID[32]; //maximum Len is 32

    APInfo();
    uint32_t getBeacons() const;
    void setBeacons(const uint32_t &value);
    uint32_t getData() const;
    void setData(const uint32_t &value);
    void incBeacons();
    void incData();
    uint8_t getChannel() const;
    void setChannel(const uint8_t &value);
    uint8_t getMB() const;
    void setMB(const uint8_t &value);

};

#endif // APINFO_H
