#ifndef STATIONINFO_H
#define STATIONINFO_H

#include "mac.h"

class StationInfo
{

    int frames{0};
    int essidLen{0};
public:
    Mac BSSID;
    Mac station;
    char ESSID[32]; //(Probe)maximum Len is 32
    StationInfo();
    int getFrames() const;
    void setFrames(int value);
    void incFrames();
    int getEssidLen() const;
    void setEssidLen(int value);
};

#endif // STATIONINFO_H
