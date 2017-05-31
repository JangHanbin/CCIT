#include <iostream>
#include "info.h"
#include "jpcaplib.h"
#include <stdio.h>
#include "errhandling.h"
#include "printdata.h"
#include "regexmethod.h"
#include "calchecksum.h"

using namespace std;

bool findHttpRequest(char *frontData);

int main(int argc, char *argv[])
{
    Info info(argc,argv);


    char errBuffer[PCAP_ERRBUF_SIZE];
    pcap_t* pcd;

    if((pcd=pcap_open_live(pcap_lookupdev(errBuffer),BUFSIZ,PROMISCUOUS,1,errBuffer))==NULL)
        errorRetn("pcap_open_live error! in Main.cpp");

    uint8_t* packetData;
    int dataLen;
    while (true)
    {
        if(!recvPacket(pcd,&(packetData),dataLen)) //if not recv packet
            break;

        uint8_t* originData=packetData;
        int originDataLen=dataLen;
        if(parseEther(&packetData,dataLen,ETHERTYPE_IP)) //parse ether_type & cmp type & move DataPointer
            if(parseIP(&packetData,dataLen,IPPROTO_TCP))
                if(parseTCPData(&packetData,dataLen))
                    if(findHttpRequest((char*)packetData))
                        if(findString(*info.rule,packetData))
                        {
                            RSTPacket RSTpacket;
                            FINPacket FINpacket;
                            makeRST(originData,originDataLen,RSTpacket,info);           //Make RST packet & save seq num
                            cout<<"Send RST Packet to Server!(Forward)"<<endl;
                            packetSend(pcd,(uint8_t*)&RSTpacket,sizeof(RSTPacket));

                            makeFIN(originData,originDataLen,FINpacket,info);
                            cout<<"Send FIN Packet to Client!(Backward)"<<endl;
                            int iphTotalLen=ntohs(FINpacket.iph.tot_len);
                            int packetLen=iphTotalLen+sizeof(struct ether_header);
                            uint8_t packet[packetLen];
                            memcpy(packet,&FINpacket,sizeof(FINPacket));
                            memcpy(packet+sizeof(FINPacket),info.blockString.c_str(),info.blockStringLen);
                            calTCPChecksum(packet+sizeof(ether_header),iphTotalLen);
                            packetSend(pcd,packet,packetLen);


                        }



    }
    return 0;
}

bool findHttpRequest(char* frontData)
{
    if(strncmp(frontData,"GET ",4)==0)
        return true;

    return false;
}
