#include "param.h"
#include <arpa/inet.h>

using namespace std;

#define STRING_IP_ADDER_LEN 17

ProtoParam::ProtoParam(int argc, char *argv[])
{
    if(!(argc!=1&&argc==4+((atoi(argv[1])-1)*2)&&(argc-2)%atoi(argv[1])==0))//least 4 (argc-2) => except command & sessionNum
    {
        usage();
    }
    this->sessionNum=atoi(argv[1]);

}
void ProtoParam::usage()
{
    cout<<"Usage : arp_spoof <session number> <sender IP> <target IP> ...."<<endl;
    cout<<"example : arp_spoof 2 192.168.0.1 192.168.0.2 192.168.0.2 192.168.0.1"<<endl;
    exit(1);
}


void Param::parse(char *argv[],int index)
{
    this->senderIp=argv[2+(index)*2];
    this->targetIp=argv[3+(index)*2];

}

void Param::initParam(char *device)
{
    this->sender_Ip=this->senderIp;
    this->target_Ip=this->targetIp;
    my_Ip.getMyIp(device); //init binary myIP Address
    inet_ntop(AF_INET,my_Ip.retnIP(),this->myIp,STRING_IP_ADDER_LEN);
    my_Mac.getMyMac(device);
}
