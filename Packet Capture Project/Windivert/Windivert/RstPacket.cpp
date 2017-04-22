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
	this->ip.HdrLength = sizeof(WINDIVERT_IPHDR)/4;// ������ 4����Ʈ ���·� �����. 4��Ʈ�� ������ ����
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


	/*�������� �۽����� �ּҸ� �ٲ�*/
	this->ip.SrcAddr = origin->ip.DstAddr;
	this->ip.DstAddr = origin->ip.SrcAddr;

	/*�������� �۽����� ��Ʈ�� �ٲ�*/
	this->tcp.SrcPort = origin->tcp.DstPort;
	this->tcp.DstPort = origin->tcp.SrcPort;

	if (origin->tcp.Ack) // flag�� Ack�� �ش��ϴ� flag�� ���õǾ�������, �� Ack ��Ŷ�̸�
		this->tcp.SeqNum = origin->tcp.AckNum; //seq , ack ����
	else
		this->tcp.SeqNum = 0;

	if (origin->tcp.Syn)// flag�� Syn�� �ش��ϴ� flag�� ���õǾ�������, �� Syn ��Ŷ�̸�
		this->tcp.AckNum = htonl(ntohl(origin->tcp.SeqNum) + 1);	//RST Packet�� �����⶧���� +1 ����
}

