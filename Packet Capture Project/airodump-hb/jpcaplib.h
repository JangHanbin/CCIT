#ifndef JPCAPLIB_H
#define JPCAPLIB_H

#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


using namespace std;

#define NONPROMISCUOUS 0
#define PROMISCUOUS 1

static char errBuf[PCAP_ERRBUF_SIZE];

#pragma pack(push,1)
struct Packet{
    struct ether_header ep;
    struct iphdr iph;
    struct tcphdr tcph;
}typedef Packet,RSTPacket, FINPacket;

#pragma pack(pop)

pcap_t* pOpen(char* device);                                        //open libpcap discrytor
bool recvPacket(pcap_t *pcd, uint8_t **packetData, int &dataLen);   //recv data & save data point packetData
bool parseEther(uint8_t **data, int& dataLen, int type);            //parse Ethernet header & cmp type if type is right move pointer to type header
bool parseIP(uint8_t** data,int& dataLen, int type);                //parse IP header & cmp type if type is right move pointer to type header
bool parseTCPData(uint8_t** data,int& dataLen);                     //parse TCP header & move pointer to TCP Data
bool parseEther(uint8_t *data,int type);                            //parse Ethernet header & cmp type if type is right
bool parseIP(uint8_t* data, int type);                              //parse IP header & cmp type if type is right
bool parseTCPData(uint8_t* data,int dataLen);                       //parse TCP header & check if exist TCP Data
void exAddr(uint8_t* originData, Packet& packet, int dataLen);      //exchange Src addr & Dest addr need to origin data point Ether & exchange ether , IP , TCP

//void makeRST(uint8_t* originData, int dataLen, RSTPacket &RSTpacket, Info &info);
//void makeFIN(uint8_t* originData, int dataLen, FINPacket &FINpacket, Info &info);     //need to call after makeRST that's why in makeRST call save Clinet Seq num & Server Seq num
#endif // JPCAPLIB_H
