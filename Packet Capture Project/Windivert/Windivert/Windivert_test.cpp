#include <iostream>
#include "parse.h"
#include <fstream>
#include <WinSock2.h>
#include "windivert.h"
#include <dbnetlib.h>
#include <iomanip>

#define MAXBUF  0xFFFF

using namespace std;


//Windivert -f "���ϸ�" 
//Windivert "�ּ��̸�"

//���� �񱳽� ,�� �����ڷ� ����Ͽ� ������� �� 

void printHexData(uint8_t* printArr, int length);
void fileOpen(ifstream & File, char* FileName);

int main(int argc, char* argv[])
{
	Parse parse(argc, argv);
	ifstream File;

	if (parse.retnIsFile()) //������ ������
		fileOpen(File, parse.retnFileName());
	
	int16_t priority = 0; //�켱������ 0���� ����
	HANDLE handle = WinDivertOpen("tcp", WINDIVERT_LAYER_NETWORK, priority, 0); //���͸� tcp��, WINDIVERT_LAYER_NETWORK=> ��Ʈ��ũ ���̾� �� 3�������� �����ϵ���,  priority�� 0���� DROP���� ����
	
	if (handle == INVALID_HANDLE_VALUE) //������ ���� �ʾ��� ��� 
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER) //������ ���� �Ķ���� ��, ���Ͱ� �߸��Ȱ��
		{
			cout << "error: filter syntax error" << endl;
			exit(EXIT_FAILURE); //EXIT_FAILURE -> 1
		}
		cout << "error: failed to open the WinDivert device : " << GetLastError()<< endl;
		cout << "Please Check if your admin" << endl;
		exit(EXIT_FAILURE);
	}

	//ť�� ũ��� �ð� ������
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LEN, 8192)) //���̰� 8192 �� �ִ� ���� �ƴϸ�(�⺻ �� : 512) ���� �̶� ������ ���������� false�� ����
	{
		cout << "error: failed to set packet queue length : " << GetLastError() << endl;
		exit(EXIT_FAILURE);
	}
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048))//�̶� �ð��� �⺻���� 512 ������ miliseconds
	{
		cout << "error: failed to set packet queue time " << GetLastError() << endl;
		exit(EXIT_FAILURE);
	}

	/*���� ��Ŷ�� ���� ���� ����*/
	uint8_t packet[MAXBUF];
	UINT packet_len; //uint-> unsigned int 
	WINDIVERT_ADDRESS addr;
	
	/* �������� ��� ����*/
	PWINDIVERT_IPHDR ip_header; //PWINDIVERT_IPHDR �̰� ��ü�� �����͸� �ǹ��ϴ� ��� 
	
	UINT8 TCP = 6;//TCP�� Protocol ID ����� ���ǵ� �κ��� ���� �� ������ ���Ŀ� ã�Ƽ� ����

	while (true)
	{
		
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len)) //��Ŷ ���� ���� ���� ó�� RecvEx�ʹ� lpOverlapped parameter�� ���̰� ����.
		{
			cout << "warning: failed to read packet : "<<GetLastError()<<endl; //������ ���� ���� ���
			continue;
		}
		ip_header = (PWINDIVERT_IPHDR)packet;

		UINT originPacketLen = packet_len;
		WinDivertSend(handle, packet, sizeof(packet), &addr, 0);
		int ip_headerLen = ip_header->HdrLength * 4;
		packet_len -= ip_headerLen; //������ ����� ���� ���� -

		if (ip_header->Protocol != TCP)  //TCP��� Ÿ���� �ƴϸ� �ٽ� ��Ŷ ����
		{
			WinDivertSend(handle, packet, sizeof(packet), &addr, &originPacketLen);
			continue;
		}
		PWINDIVERT_TCPHDR tcp_header = (PWINDIVERT_TCPHDR)(packet + ip_headerLen); //tcp��� ���� 

		int tcp_headerLen= tcp_header->HdrLength * 4;
		packet_len -= tcp_headerLen;
		
		if (packet_len <= 0)//data�κ��� ������
		{
			WinDivertSend(handle, packet, sizeof(packet), &addr, &originPacketLen);
			continue; //��Ŷ �ٽ� ĸ��
		}
			


	
		uint8_t *tcpData=(uint8_t*)((uint8_t*)tcp_header+ tcp_headerLen) ;//������ �κк��� ���� �̶� (uint8_t*)tcp_header�� ĳ���� ������������ �ּ��� ��(tcp���)�� ũ�� 20 �� �����ŭ headerLen�� ������ �̻��� ��ġ ����
		UINT32 *host;
		UINT32 HostValue=0x486f7374; //Host 
		uint8_t* sHost;//���ڿ��� ���� �ּҸ� ����
		int hostLen = 0;
		while (packet_len-- > 3) //������ ���̷� ���� 3�������� ����
		{
			host = (UINT32*)tcpData;
			if (ntohl(*host) == HostValue) //Host�� ��ġ�� ã���� 
			{
				uint8_t* tmp = (uint8_t*)host;
				
				while (*tmp++ != 0x20); //Host : test.gilgil.net���� ���� �����ʹ� Host�� H�� ����Ű�� �����Ƿ� Host�� ���� �ּ��� ���ڸ� ����Ű�� �� 

				sHost = tmp ; // ȣ��Ʈ�� ���� ������ ���� ���� (�Ʒ����� tcpData���� �����ϹǷ� �����ص�)
				tcpData = tmp; //�������� ���� ��ġ�� ȣ��Ʈ ���� ������ ������ �̵�
				while (*tcpData!=0x0d&&*(tcpData+1)!=0x0a) //0d 0a �� \r \n�� ã�������� 
				{
					tcpData++; //�������� ���� ��ġ�� �Ű���
					hostLen++; //ȣ��Ʈ�� ���� üũ
				}
				break;
			}
			else {
				tcpData++;
			}
		}

		uint8_t* hostInPacket = new uint8_t[hostLen+1]; //���̸�ŭ ���� �Ҵ�
		memcpy(hostInPacket, sHost, hostLen); // �ش� ���ڿ� ���� 
		hostInPacket[hostLen] = 0; //�� �߰�
		
		if (!parse.retnIsFile()) //������ ������ ��, ���ڷ� �ּҸ� ������
		{
			if (strcmp((char*)hostInPacket, parse.retnHost()) == 0)
			{
				cout << "Host " << parse.retnHost() << " Detected !!" << endl;
			}
			else { //�ش� ȣ��Ʈ�� �ƴ϶�� 
				WinDivertSend(handle, packet, sizeof(packet), &addr, &originPacketLen);
			}
		}
}
	/*
	char tmp[100];

	while (!File.eof()) {

		File.getline(tmp,100);
		cout << tmp << endl;

	}
	*/

	File.close();
}

void fileOpen(ifstream & File, char* FileName)
{
	File.open(FileName, ios::in);
	if (!File.is_open())
	{
		perror("File open");
		exit(1);
	}
}


void printHexData(uint8_t* printArr, int length)
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