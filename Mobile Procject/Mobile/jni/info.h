#ifndef INFO_H
#define INFO_H

#include "mac.h"
#include "ip.h"

class Info
{


public:
    Info();
    char* myMAC;
    char* gatewayMAC;
    char* myIP;
    char* proxyIP;
    Mac my_MAC;
    Mac gateway_MAC;
    Ip my_IP;
    Ip proxy_IP;
};

#endif // INFO_H
