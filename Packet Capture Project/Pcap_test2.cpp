#include <iostream>
#include <pcap.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <iomanip>
#include <cstdio>
#include <string.h>

using namespace std;

#define PROMISCUOUS 1 //Get every packet from Ethernet
#define NONPROMISCUOUS 0 //Get only mine from Ethernet

struct ip *iph; //Struct of IP
struct tcphdr *tcph; //Struct of TCP


void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);
void printMac(u_int8_t *addr);
int lengthRet(int length, int minusLen);

int main(int argc, char* argv[]) //Device , Filter
{
    if(argc!=3)
    {
            cout<<"Usage : Pcap [Device Name] [\"Filter\"]"<<endl;
            cout<<"You can fine filter rules at \"www.winpcap.org/docs/docs_40_2/html/group_language.html\""<<endl;
            exit(1);
    }

    char * device = argv[1];
    int ret;
    char* netAddress;
    char* netMask;
    bpf_u_int32 netp; //IP
    bpf_u_int32 maskp; //Subnet Mask
    char errBuf[PCAP_ERRBUF_SIZE];
    struct in_addr addr;//Struct to save IPv4
    char address[16];
    cout<<"Device :"<<device<<endl;
    if(ret = pcap_lookupnet(device,&netp,&maskp,errBuf) <0) //Get Network , Subnet mask about Device
    {														//error => return -1 & error content => errBuf
            perror(errBuf);									//error => print errBuf & exit
            exit(1);
    }

    addr.s_addr = netp;
    inet_ntop(AF_INET,&(addr.s_addr),address,sizeof(address));
    //strcpy(netAddress,address);
    netAddress=address;
    if(netAddress==NULL)//inet_ntoa => convert ulong type to Dotted-Decimal Notation
    {
        perror("inet_ntop");
        exit(1);
    }
    cout<<"Network Address : "<< netAddress <<endl;

    addr.s_addr = maskp;
    inet_ntop(AF_INET,&addr,address,sizeof(address));
    netMask=address;
    cout<<"Subnet Mask : "<<netMask<<endl;

    pcap_t *pcd; //Packet capture descriptor


    //BUFSIZ is a optimum size (defined in csdio)
    //Get packet capture descriptor from Device
    if((pcd = pcap_open_live(device,BUFSIZ, NONPROMISCUOUS , 1, errBuf))==NULL)
    {
            perror(errBuf);
            exit(1);
    }


    struct bpf_program fp;


    if(pcap_compile(pcd, &fp, argv[2] , 0, netp)==-1) //Set fp by filter rule(argv[2])
    {
            cout<<"Setfilter error!!!"<<endl;
            exit(1);
    }

    if(pcap_setfilter(pcd, &fp) == -1) //apply packet filter
    {
            cout<<"Setfilter error"<<endl;
            exit(1);
    }


    pcap_loop(pcd, 0, callback, NULL); //count 1 -> 0 infinity loop



    return 0;

}



//packet => recevied pakcet
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{

    struct ether_header *ep;
    unsigned short ether_type;
    int length=pkthdr->len;


    ep = (struct ether_header *)packet; //Save Ethernet Header
    cout<<"Information of Ehernet"<<endl;
    cout<<"Src Mac Address : ";
    printMac(ep->ether_shost);

    cout<<"Dest Mak Address : ";
    printMac(ep->ether_dhost);


    cout<<endl<<endl;




    ether_type = ntohs(ep->ether_type);// ntohs(network to host short)
                                       // network => little endian


    length = lengthRet(length, sizeof(ep));

    if(ether_type == ETHERTYPE_IP)	//next protocol is IP(0x0800) defined in netinet->if_ether
    {

        packet += sizeof(struct ether_header);//To bring IP header
        char address[16];

        iph = (struct ip *)packet;
        cout<<"Information of IP"<<endl;
        inet_ntop(AF_INET,&(iph->ip_src),address,sizeof(address));//change inet_ntoa(iph->ip_src) to inet_ntop
        cout<<"Src IP Address : "<<address<<endl;
        inet_ntop(AF_INET,&(iph->ip_dst),address,sizeof(address));
        cout<<"Dest IP Address : "<<address<<endl;
        cout<<endl<<endl;

        length = lengthRet(length, sizeof(iph));

        if(iph->ip_p== IPPROTO_TCP) //next protocol is TCP
        {
            packet = packet + iph->ip_hl * 4;
            tcph =(struct tcphdr *)packet;					 //TCP Header
                                                             //iph->ip_hl => Header length
                                                             //ip_hl is word so ip_hl * 4
                                                             //linux word => 4byte
            cout<<"Informaiton of TCP"<<endl;
            cout<<"Src Port : "<<ntohs(tcph->source)<<endl;
            cout<<"Dst Port : "<<ntohs(tcph->dest)<<endl;
            cout<<endl<<endl;

            length = lengthRet(length, (tcph->th_off)*4); //return length th_off = offset type => u_int_8
            packet += (tcph->th_off)*4; //To print Data Section
        }


       unsigned char printArr[length]; // Hex -> 4bit , Hex * 2 = 8bit => unsigned char(1byte) => unsigned 8bit int


        for(int i=0;i<length;i++) //save packet to arr
        {
            printArr[i]=(*packet++);
        }



        for(int i=0;i<length;i++) //print data
        {
            if(i%16==0)
                cout<<endl;
            cout<<setfill('0');
            cout<<setw(2)<<hex<<(int)printArr[i]<<" ";
        }
        cout<<dec;

        int location=0;
        for(int i=0;i <length-3;i++) //find Host
        {
            if(printArr[i]=='H'&&printArr[i+1]=='o'&&printArr[i+2]=='s'&&printArr[i+3]=='t')
                location=i;
        }

        cout<<endl;

        if(location!=0) //if find Host location
        {
            while (printArr[location]!=11&&printArr[location+1]!=10)// reach 0d 0a
            {
                cout<<printArr[location++];
            }
        }

        location=0;
        cout << endl << endl;

    }else{
            cout<<"This Packet is not IP Packet"<<endl;
    }

}



void printMac(u_int8_t *addr)
{

    int sizeOfMac=6;//mac address => 48bit
                    //mac use hexadecimal number
                    //Ex) AB:CD:EF:GH:YJ:KL
                    //hexadecimal number use 4bit per 1 num
                    //0 0 0 0 => 0
                    //1 1 1 1 => F => 15

    for(int i=0; i<sizeOfMac;i++)
    {
            printf("%02x",addr[i]);
            if(i!=sizeOfMac-1)
                    printf(":");

    }


    cout<<endl;
}

int lengthRet(int length, int minusLen)
{
    length -= minusLen;
    return length;
}

/************************Information***************************/
//Ethernet & IP Header has a next protocol Info.
//Ethernet => ether_type IP => ip_p
//***********************Flow chart****************************
//pcap_lookupnet => Get a Device name & Net & Subnet
//pcap_open_live()=> Make a PCD(Packet Capture Descriptor)
//pcap_compile() //Set fp by filter rule
//pcap_setfilter() //apply packet filter
//pcap_loop(); //callback a Function by PCD
//Function






