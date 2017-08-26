#include "apinfo.h"

uint32_t APInfo::getBeacons() const
{
    return beacons;
}

void APInfo::setBeacons(const uint32_t &value)
{
    beacons = value;
}

uint32_t APInfo::getData() const
{
    return data;
}

void APInfo::setData(const uint32_t &value)
{
    data = value;
}

void APInfo::incBeacons()
{
    beacons+=1;
}

void APInfo::incData()
{
    data+=1;
}

uint8_t APInfo::getChannel() const
{
    return channel;
}

void APInfo::setChannel(const uint8_t &value)
{
    channel = value;
}

uint8_t APInfo::getMB() const
{
    return MB;
}

void APInfo::setMB(const uint8_t &value)
{
    MB = value;
}

int APInfo::getEssidLen() const
{
    return essidLen;
}

void APInfo::setEssidLen(int value)
{
    essidLen = value;
}

APInfo::APInfo()
{

}
