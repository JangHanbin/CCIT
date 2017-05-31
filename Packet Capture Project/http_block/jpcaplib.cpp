#include "jpcaplib.h"
#include <cstring>
#include <cstdlib>
#include <ctime>
#include "calchecksum.h"
#include "printdata.h"



bool recvPacket(pcap_t* pcd, uint8_t **packetData,int& dataLen)
{

    const u_char *pkt_data;
    struct pcap_pkthdr *pktHeader;
    int valueOfNextEx;

    while(true)
    {
        valueOfNextEx=pcap_next_ex(pcd,&pktHeader,&pkt_data);

        switch (valueOfNextEx)
        {
            case 1:
                *packetData=(uint8_t*)pkt_data;
                dataLen=pktHeader->caplen;
                return true;
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
                return false;
            }
    }
}

bool parseEther(uint8_t** data,int& dataLen,int type)
{
    struct ether_header *ep=(struct ether_header*)*data;

    if(ntohs(ep->ether_type)==type)
    {

        *data=*data+sizeof(struct ether_header);
        dataLen-=sizeof(struct ether_header);
        return true;
    }


    return false;
}

bool parseIP(uint8_t** data,int& dataLen, int type)
{

    struct iphdr *iph=(struct iphdr*)*data;

    if(iph->protocol==type)
    {

        *data=*data+(iph->ihl*4);
        dataLen-=(iph->ihl*4);
        return true;
    }


    return false;
}



bool parseTCPData(uint8_t **data, int &dataLen)
{
    struct tcphdr* tcph = (struct tcphdr*)*data;
    *data=*data+(tcph->doff*4);
    dataLen-=(tcph->doff*4);

    if(dataLen<=0)
        return false;
    else
        return true;

}

void packetSend(pcap_t *pcd, uint8_t *data,int dataLen)
{
    pcap_sendpacket(pcd,data,dataLen);
}



/* Make RST & FIN don't need to check parse method Exception. Because already checked in main*/

void makeRST(uint8_t *originData, int dataLen,RSTPacket& RSTpacket,Info& info)
{

    //Make Ehter_Header
    struct ether_header *ep=(struct ether_header*)originData;
    memcpy(&RSTpacket.ep,ep,sizeof(struct ether_header));

    parseEther(&originData,dataLen,ETHERTYPE_IP); //move pointer to IP header

    //Make IP Header
    //need to modify header total Length & checksum & TTL
    struct iphdr *iph=(struct iphdr*)originData;
    memcpy(&RSTpacket.iph,iph,sizeof(struct iphdr));
    RSTpacket.iph.tot_len=htons(sizeof(iphdr)+sizeof(tcphdr)); //40
    RSTpacket.iph.ttl=64+(rand()%(255-64));

    calIPChecksum((uint8_t*)&RSTpacket.iph);


    //Make TCP Header
    //need to modify TCP checksum & header Len & add seq num + dataLen & set flag
    parseIP(&originData,dataLen,IPPROTO_TCP); //move pointer to TCP header
    memcpy(&RSTpacket.tcph,originData,sizeof(tcphdr));

    //Set Flags
    RSTpacket.tcph.doff=5;
    parseTCPData(&originData,dataLen);
    RSTpacket.tcph.seq=htonl(ntohl(RSTpacket.tcph.seq)+dataLen);
    RSTpacket.tcph.res1=0;
    RSTpacket.tcph.fin=0;
    RSTpacket.tcph.syn=0;
    RSTpacket.tcph.rst=1;
    RSTpacket.tcph.psh=0;
    RSTpacket.tcph.ack=1;
    RSTpacket.tcph.urg=0;
    RSTpacket.tcph.res2=0;



    info.cSeq=RSTpacket.tcph.seq;                           //save seq num
    info.sSeq=RSTpacket.tcph.ack_seq;                           //save server seq num



    calTCPChecksum((uint8_t*)&RSTpacket.iph,sizeof(iphdr)+sizeof(tcphdr));
}

void exAddr(uint8_t *originData, Packet &packet,int dataLen)
{
    //Exchange Ether Addr
    struct ether_header *ep = (struct ether_header*)originData;
    memcpy(packet.ep.ether_dhost,ep->ether_shost,ETHER_ADDR_LEN);
    memcpy(packet.ep.ether_shost,ep->ether_dhost,ETHER_ADDR_LEN);


    //Exchange IP Addr
    parseEther(&originData,dataLen,ETHERTYPE_IP); //originData at IP header
    struct iphdr *iph=(struct iphdr*)originData;
    packet.iph.saddr=iph->daddr;
    packet.iph.daddr=iph->saddr;

    //Exchange TCP Port
    parseIP(&originData,dataLen,IPPROTO_TCP);

    struct tcphdr *tcph=(struct tcphdr*)originData;
    packet.tcph.source=tcph->dest;
    packet.tcph.dest=tcph->source;


}

void makeFIN(uint8_t *originData, int dataLen, FINPacket &FINpacket, Info &info)
{

    //do not cpy memcpy(&Packet,originData,sizeof(Packet)
    //ipheader & tcp header length changeable so use parse.

    uint8_t* packet=originData;

    //Make Ether_Header
    struct ether_header *ep = (struct ether_header*)packet;
    memcpy(&FINpacket.ep,ep,sizeof(struct ether_header));

    //Make IP_Header
    parseEther(&packet,dataLen,ETHERTYPE_IP); //packet at IP header
    struct iphdr *iph=(struct iphdr*)packet;
    memcpy(&FINpacket.iph,iph,sizeof(struct iphdr));

    //Make TCP_Header
    parseIP(&packet,dataLen,IPPROTO_TCP);//packet at TCP header
    struct tcphdr *tcph=(struct tcphdr*)packet;
    memcpy(&FINpacket.tcph,tcph,sizeof(struct tcphdr));

    //exchange Addr
    exAddr(originData,FINpacket,dataLen);

    uint16_t totalLen=sizeof(iphdr)+sizeof(tcphdr)+info.blockStringLen;
    cout<<"total Len :"<<totalLen<<endl;
    FINpacket.iph.tot_len=htons(totalLen);
    FINpacket.iph.ttl=64+(rand()%(255-64));

    calIPChecksum((uint8_t*)&FINpacket.iph);


    //Set Flags
    FINpacket.tcph.window=0;
    FINpacket.tcph.doff=5;
    FINpacket.tcph.seq=info.sSeq;
    FINpacket.tcph.ack_seq=info.cSeq;
    FINpacket.tcph.res1=0;
    FINpacket.tcph.fin=1;
    FINpacket.tcph.syn=0;
    FINpacket.tcph.rst=0;
    FINpacket.tcph.psh=0;
    FINpacket.tcph.ack=1;
    FINpacket.tcph.urg=0;
    FINpacket.tcph.res2=0;


  //  calTCPChecksum((uint8_t*)&FINpacket.iph,totalLen);
}

