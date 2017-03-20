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
#define Host 0x486f7374



void printPacket( const struct pcap_pkthdr *pkthdr, const u_char *packet);
void printMac(u_int8_t *addr);
int lengthRet(int length, int minusLen);
void printHexData(u_int8_t *printArr, int length);


int main(int argc, char* argv[]) //Device , Filter
{
    if(argc!=3)
    {
            cout<<"Usage : Pcap [Device Name] [\"Filter\"]"<<endl;
            cout<<"You can fine filter rules at \"www.winpcap.org/docs/docs_40_2/html/group_language.html\""<<endl;
            exit(1);
    }

    char * device = argv[1];
    char* netMask;
    bpf_u_int32 netp; //IP
    bpf_u_int32 maskp; //Subnet Mask
    char errBuf[PCAP_ERRBUF_SIZE];

    cout<<"Device :"<<device<<endl;
    int ret;
    if((ret = pcap_lookupnet(device,&netp,&maskp,errBuf)) <0) //Get Network , Subnet mask about Device
    {														//error => return -1 & error content => errBuf
            perror(errBuf);									//error => print errBuf & exit
            exit(1);
    }

    struct in_addr addr;//Struct to save IPv4
    addr.s_addr = netp;

    char address[16];
    inet_ntop(AF_INET,&(addr.s_addr),address,sizeof(address));

    char* netAddress=address;
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

    cout<<endl<<endl;

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


    const u_char *pkt_data;//packet
    struct pcap_pkthdr *pktHeader; //Packet Header

    /*  pcap_next_ex means of return value
     * // return 1 if the packet has been read without problems.
     * // return 0 if the timeout set with pcap_open_live() has elapsed(in this case pkt_header , pkt_data don't point to a valid packet
     * // return -1 if an error occurred
     * // return -2 if EOF was reached reading from an offline capture
     */
    int valueOfNextEx;

    while(true)
    {
        valueOfNextEx = pcap_next_ex(pcd,&pktHeader,&pkt_data);

        switch (valueOfNextEx)
        {
            case 1:
                 printPacket(pktHeader,pkt_data);
                break;
            case 0:
                cout<<"need a sec.. to packet capture"<<endl;
                continue;
            case -1:
                perror("pcap_next_ex function has an error!!!");
                exit(1);
            case -2:
                cout<<"the packet have reached EOF!!"<<endl;
                exit(0);
            default:
                break;
        }


    }




    return 0;

}



//packet => recevied pakcet
void printPacket(const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    (void)pkthdr; //trash

    struct ether_header *ep;
    unsigned short ether_type;


    ep = (struct ether_header *)packet; //Save Ethernet Header
    cout<<"------------------------------------------------"<<endl;
    cout<<"Information of Ehernet"<<endl;
    cout<<"Src Mac Address : ";
    printMac(ep->ether_shost);

    cout<<"Dest Mac Address : ";
    printMac(ep->ether_dhost);


    cout<<endl<<endl;




    ether_type = ntohs(ep->ether_type);// ntohs(network to host short)
                                       // network => little endian


    if(ether_type != ETHERTYPE_IP) exit(0);

    //next protocol is IP(0x0800) defined in netinet->if_ether

    struct ip *iph; //Struct of IP
    iph = (struct ip *)((u_char*)ep+sizeof(struct ether_header));//To bring IP header
    char address[16];

    cout<<"Information of IP"<<endl;
    inet_ntop(AF_INET,&(iph->ip_src),address,sizeof(address));//change inet_ntoa(iph->ip_src) to inet_ntop
    cout<<"Src IP Address : "<<address<<endl;
    inet_ntop(AF_INET,&(iph->ip_dst),address,sizeof(address));
    cout<<"Dest IP Address : "<<address<<endl;
    cout<<endl<<endl;


    int length = ntohs(iph->ip_len); //length -> total length -> iph + tcph+ data section.

    length = lengthRet(length,iph->ip_hl*4);

    if(iph->ip_p!= IPPROTO_TCP)
    {
        cout<<"Next protocol is not TCP!!"<<endl;
        exit(0);
    }

    //next protocol is TCP

    struct tcphdr *tcph; //Struct of TCP


    tcph =(struct tcphdr *)((u_char*)iph+(iph->ip_hl *4));	 //TCP Header
                                                     //iph->ip_hl => Header length
                                                     //ip_hl is word so ip_hl * 4
                                                     //linux word => 4byte

   // printHexData((u_int8_t*)packet,pkthdr->len);
    cout<<"Informaiton of TCP"<<endl;
    cout<<"Src Port : "<<ntohs(tcph->source)<<endl;
    cout<<"Dst Port : "<<ntohs(tcph->dest)<<endl;
    cout<<endl<<endl;

    length = lengthRet(length, (tcph->th_off)*4); //return length th_off = offset type => u_int_8
     //To print Data Section

    if(length<=0)
    {
        cout<<"There is no HTTP data"<<endl;
    }



    u_int8_t* printArr = (u_int8_t*)((u_char*)tcph+((tcph->th_off)*4));
    printHexData(printArr,length);

    u_int32_t *host;

    while(length-->3)//print host
    {
        host = (u_int32_t *)printArr;
        if(ntohl(*host)==Host)
                while(*printArr!=0x0d&&*(printArr+1)!=0x0a)
                   {
                          cout<<*printArr++;
                   }
        else
            printArr++;

    }
    cout<<endl;
    cout<<dec<<endl;





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


void printHexData(u_int8_t* printArr,int length)
{
    for(int i=0;i<length;i++) //print data
    {
        if(i%16==0)
            cout<<endl;
        cout<<setfill('0');
        cout<<setw(2)<<hex<<(int)printArr[i]<<" ";
    }



    cout<<dec<<endl<<endl;
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






