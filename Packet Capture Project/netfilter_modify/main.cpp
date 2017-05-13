#include <iostream>
#include "parse.h"
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include "printdata.h"
#include <assert.h>
#include <regex>
#include <regexmethod.h>
#include <calchecksum.h>

using namespace std;

void getError(string error);
static u_int32_t checkPacket (struct nfq_data *tb, int& flag, Parse *parse, uint8_t *mData, uint32_t &mDataLen);
static int callback(struct nfq_q_handle *qhandle, struct nfgenmsg *nfmsg,struct nfq_data *nfa, void *data);
uint8_t *modifyPoint(uint8_t* data, int& len, int hdrlen);

int main(int argc, char *argv[])
{
    Parse parse(argc,argv);
    struct nfq_handle* handle=nfq_open();

    /*open lib handle*/
    if(!handle)
        getError("error during nfq_open()");

    /*unbinding existing nf_queue handler for AF_INET*/
    if(nfq_unbind_pf(handle,AF_INET)<0)
        getError("error during nfq_unbind_pf()");

    /*binding nfnetlink_queue as nf_queue handler for AF_INET*/
    if(nfq_bind_pf(handle,AF_INET)<0)
        getError("error during nfq_bind_pf()");

    /*binding this socket to queue '0'*/
    struct nfq_q_handle* qhandle=nfq_create_queue(handle,0,&callback,&parse);
    if(!qhandle)
        getError("error during nfq_create_queue()");

    /*setting copy_packet mode*/

    if(nfq_set_mode(qhandle,NFQNL_COPY_PACKET,0xffff)<0)
        getError("can't set packet_copy mode");

    int fd=nfq_fd(handle);
    int rv=0;
    char buf[4096] __attribute__ ((aligned));


    while (true)
    {
        if((rv=recv(fd,buf,sizeof(buf),0))>=0) //if recv success
            nfq_handle_packet(handle,buf,rv); //call callback method

    }
    return 0;
}

void getError(string error)
{
    perror(error.c_str());
    exit(1);
}

static u_int32_t checkPacket(nfq_data *tb, int &flag,Parse* parse,uint8_t* mData,uint32_t &mDataLen)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph)
        id = ntohl(ph->packet_id);

    uint8_t* data;
    int ret=nfq_get_payload(tb,&data);

    //backup data point
    uint8_t* dataStart=data;

    //Make Modified Packet buf
    mDataLen = ret;
    parse->allocPacket(mDataLen);
    mData = parse->packet;


    if(ret<=0) //no ip packet
    {
        cout<<"no Payload Packet"<<endl;
        flag=NF_ACCEPT;
        return id;
    }
    struct iphdr *iph=(struct iphdr*)data;
    uint8_t hdrLen=iph->ihl*4;
    data=modifyPoint(data,ret,hdrLen);


    assert(iph->protocol==IPPROTO_TCP&& "Protocol type must be TCP !!!");
    struct tcphdr *tchph=(struct tcphdr*)data;
    hdrLen=tchph->th_off*4;
    data=modifyPoint(data,ret,hdrLen);

    //packet data works

    if(fixEncoding(*parse->retEncodingRule(),(uint8_t*)data,"Accept-Encoding-HB:"))
        cout<<"fixed encoding type"<<endl;

    if(findAndFixStirng(*parse->retRule(),(uint8_t*)data,true,parse->retModifyString()))
        cout<<"Change string "<<parse->retFindString().c_str()<<"->"<<parse->retModifyString().c_str()<<endl;


    memcpy(mData,dataStart,mDataLen);
    calTCPChecksum(mData,mDataLen); //save tcp checksum to field & return value is checksum
    calIPChecksum(mData);

    return id;
}

static int callback(nfq_q_handle *qhandle, nfgenmsg *nfmsg, nfq_data *nfa, void *data)
{
    (void)nfmsg;
    int flag;
    Parse *parse = (Parse*)data;
    //uint8_t* mData=nullptr;
    //uint32_t mDataLen;
    u_int32_t id = checkPacket(nfa,flag,(Parse*)data,parse->packet,parse->packetLen); //call another method
    //cout<<mDataLen<<endl;
    //printByHexData(parse->packet,parse->packetLen);
    return nfq_set_verdict(qhandle, id, NF_ACCEPT, parse->packetLen,parse->packet);

}

uint8_t* modifyPoint(uint8_t* data,int& len,int hdrlen)
{

    len-=hdrlen;
    return data+=hdrlen;
}
