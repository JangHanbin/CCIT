#include <iostream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <info.h>

using namespace std;

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

int main(int argc, char *argv[])
{
    char errBuf[PCAP_ERRBUF_SIZE];
    char* device = pcap_lookupdev(errBuf); //get device

    /*init pcd*/
    pcap_t *pcd;
    if((pcd = pcap_open_live(device,BUFSIZ,PROMISCUOUS,1,errBuf))==NULL)
    {
        perror(errBuf);
        exit(1);
    }
    /*init pcd*/
    struct hostent *host=gethostbyname("hanbin.iptime.org");
    if(!host)
    {
        perror("Gethostbyname Error!!");
        exit(1);
    }


    int sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP); //init TCP Sock

    sockaddr_in sockAddr;
    sockAddr.sin_port=htons(8888);
    sockAddr.sin_family=AF_INET;
    sockAddr.sin_addr.s_addr=*(unsigned long*)host->h_addr_list[0];


    Info info;;

    info.proxyIP=inet_ntoa(sockAddr.sin_addr);
    cout<<"Proxy Server IP : "<<info.proxyIP<<endl;

    if(connect(sock,(struct sockaddr*)&sockAddr,sizeof(sockAddr)))
    {
        perror("Connect error!");
        exit(1);
    }
    return 0;
}
