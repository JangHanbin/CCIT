#ifndef REGEXMETHOD_H
#define REGEXMETHOD_H


#include <cstring>
#include <regex>

bool findAndFixStirng(std::regex rg, uint8_t* data,bool flag,std::string reString);
bool fixEncoding(std::regex rg, uint8_t* data,std::string reString);
#endif // REGEXMETHOD_H
