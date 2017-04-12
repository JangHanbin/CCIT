#ifndef PARAM_H
#define PARAM_H

#include <iostream>
#include <cstring>
#include "mac.h"
#include "ip.h"

class ProtoParam{
public:
    ProtoParam(int argc, char *argv[]);
    int sessionNum=1; //default 1

    void usage();
};

class Param{
public:

    //string data
    char* senderIp;
    char* targetIp;
    char myIp[17];
    //binary data
    Ip sender_Ip;
    Ip target_Ip;
    Ip my_Ip;
    Mac sender_Mac;
    Mac target_Mac;
    Mac my_Mac;
    void parse(char* argv[], int index);
    void initParam(char* device);
    void printInfo();

};

#endif // PARAM_H
