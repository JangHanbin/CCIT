#include "stationinfo.h"

int StationInfo::getFrames() const
{
    return frames;
}

void StationInfo::setFrames(int value)
{
    frames = value;
}

void StationInfo::incFrames()
{
    frames+=1;
}

int StationInfo::getEssidLen() const
{
    return essidLen;
}

void StationInfo::setEssidLen(int value)
{
    essidLen = value;
}

StationInfo::StationInfo()
{

}
