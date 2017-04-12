#include <iostream>
#include <pcap.h>
#include <iomanip>
#include <thread>
#include "param.h"
#include <unistd.h>

using namespace std;

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

void parseClass(Param* param, char *argv[], int sessionNum);
void initClass(Param* param, char* device, int sessionNum);
void printByHexData(uint8_t* printArr,int length);
void printByMAC(u_int8_t *printArr,int length);
void printLine();
int findARPReply(pcap_t* pcd, Mac* retnMAC, uint32_t* find_IP, uint32_t* my_IP);
void findSenderMAC(pcap_t *pcd,Param* param,int sessionNum);
void getSenderMAC(pcap_t *pcd,Param* param,int sessionNum);
void getTargetMAC(pcap_t* pcd,Mac *retnMAC,uint32_t* find_IP,uint32_t* my_IP);
void sendARPReguest(Param param,uint32_t*findIP,int print,pcap_t *pcd);

struct ARPPacket{
    struct ether_header eh;
    struct ether_arp arp;
};


int main(int argc, char *argv[])
{
    ProtoParam protoParam(argc,argv); //check arg & init sessionNum

    char errBuf[PCAP_ERRBUF_SIZE];
    char* device = pcap_lookupdev(errBuf); //get device

    Param param[protoParam.sessionNum]; //make class

    parseClass(param,argv,protoParam.sessionNum);
    initClass(param,device,protoParam.sessionNum);

    /*init pcd*/
    pcap_t *pcd;
    if((pcd = pcap_open_live(device,BUFSIZ,NONPROMISCUOUS,1,errBuf))==NULL)
    {
        perror(errBuf);
        exit(1);
    }
    /*init pcd*/


    findSenderMAC(pcd,param,protoParam.sessionNum);

    for (int i = 0; i < protoParam.sessionNum; ++i) {
        cout<<"Attacker MAC : ";
        printByMAC(param[i].my_Mac.retnMac(),ETHER_ADDR_LEN);
        cout<<"Sender MAC : ";
        printByMAC(param[i].sender_Mac.retnMac(),ETHER_ADDR_LEN);

    }

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

void printByHexData(u_int8_t *printArr, int length)
{

    for(int i=0;i<length;i++)
    {
        if(i%16==0)
            cout<<endl;
        cout<<setfill('0');
        cout<<setw(2)<<hex<<(int)printArr[i]<<" ";

    }

    cout<<dec<<endl;
    printLine();
}

void printByMAC(u_int8_t *printArr,int length)
{
    for(int i=0;i<length;i++)
    {
        cout<<setfill('0');
        cout<<setw(2)<<hex<<(int)printArr[i];
        if(i!=5)
            cout<<":";

    }

    cout<<dec<<endl<<endl;
}

void printLine()
{
    cout<<"-----------------------------------------------"<<endl;
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
                       cout<<"detected"<<endl;
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

void findSenderMAC(pcap_t *pcd,Param* param,int sessionNum)
{

    for (int i = 0; i < sessionNum; ++i) {
        thread t1(&findARPReply,pcd,&param[i].sender_Mac,param[i].sender_Ip.retnIP(),param[i].my_Ip.retnIP());
        sleep(3);
        thread t2(&sendARPReguest,param[i],param[i].sender_Ip.retnIP(),0,pcd);
        t1.join();
        t2.join();
    }

}

/*
void getTargetMAC(pcap_t *pcd, Mac *retnMAC, uint32_t *find_IP, uint32_t *my_IP)
{
    for (int i = 0; i < protoParam.sessionNum; ++i) {
        thread t1(&findARPReply,pcd,&param[i].target_Mac,param[i].target_Ip.retnIP(),param[i].my_Ip.retnIP());
        sleep(2);
    }
}
*/



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
