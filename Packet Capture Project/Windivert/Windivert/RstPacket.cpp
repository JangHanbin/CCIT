#include "RstPacket.h"
#include <iostream>
#include <iomanip>

using namespace std;


void printHexData1(uint8_t* printArr, int length)
{
	for (int i = 0; i < length; i++)
	{
		if (i % 16 == 0)
			cout << endl;
		cout << setfill('0');
		cout << setw(2) << hex << (int)printArr[i] << " ";


	}

	cout << dec << endl << endl;
}

RstPacket::RstPacket(uint8_t* packet)
{
	this->ip.Version = 4;
	this->ip.HdrLength = sizeof(WINDIVERT_IPHDR)/4;// 나누기 4바이트 형태로 저장됨. 4비트를 가지기 때문
	this->ip.TTL = 128;
	this->ip.Id = ntohs(0xDEAD);
	this->tcp.Rst = 1;
	this->tcp.Ack = 1;
	this->ip.TOS = 0;
	this->ip.FragOff0 = 0;
	this->ip.Checksum = 0;

	this->ip.Length = sizeof(RstPacket);
	this->ip.Protocol = IPPROTO_TCP;
	this->tcp.HdrLength = sizeof(WINDIVERT_TCPHDR) / 4;

	makeRSTPacket(packet);
}

void RstPacket::makeRSTPacket(uint8_t* packet)

{

	RstPacket *origin = (RstPacket*)packet;


	/*목적지와 송신지의 주소를 바꿈*/
	this->ip.SrcAddr = origin->ip.DstAddr;
	this->ip.DstAddr = origin->ip.SrcAddr;

	/*목적지와 송신지의 포트를 바꿈*/
	this->tcp.SrcPort = origin->tcp.DstPort;
	this->tcp.DstPort = origin->tcp.SrcPort;

	if (origin->tcp.Ack) // flag중 Ack에 해당하는 flag가 셋팅되어있으면, 즉 Ack 패킷이면
		this->tcp.SeqNum = origin->tcp.AckNum; //seq , ack 변경
	else
		this->tcp.SeqNum = 0;

	if (origin->tcp.Syn)// flag중 Syn에 해당하는 flag가 셋팅되어있으면, 즉 Syn 패킷이면
		this->tcp.AckNum = htonl(ntohl(origin->tcp.SeqNum) + 1);	//RST Packet을 보내기때문에 +1 해줌
}

