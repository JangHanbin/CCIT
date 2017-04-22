#include <iostream>
#include "parse.h"
#include <fstream>
#include <WinSock2.h>
#include "windivert.h"
#include <dbnetlib.h>
#include <iomanip>
#include <time.h>
#include "RstPacket.h"

#define MAXBUF  0xFFFF

using namespace std;


//Windivert -f "���ϸ�" 
//Windivert "�ּ��̸�"

//���� �񱳽� ,�� �����ڷ� ����Ͽ� ������� �� 

void printHexData(uint8_t* printArr, int length);
void fileOpen(ifstream & File, char* FileName);
bool sendPacket(HANDLE handle, PVOID packet, int len, WINDIVERT_ADDRESS * addr);
int main(int argc, char* argv[])
{
	Parse parse(argc, argv);
	ifstream File;
	char *domainInFile;
	int fileLength = 0;

	if (parse.retnIsFile()) //������ ������
	{
		fileOpen(File, parse.retnFileName()); //���̳ʸ� ���� ���� 
		File.seekg(0, ios::end); //������ ������Ʈ�� ���������� ����
		fileLength = File.tellg(); //������ �� ���� ��ȯ
		File.seekg(0, ios::beg); //ó������ ����

		domainInFile = new char[fileLength + 1]; //������ �� ����+1 ��ŭ ���� �Ҵ�
		domainInFile[fileLength] = 0;//���߰� ���� �񱳽ÿ� ������ ������ ���ڿ��̹Ƿ� nulló�� 
		File.read(domainInFile, fileLength);//������ ��ü ���� 

	}

	int16_t priority = 0; //�켱������ 0���� ����
	HANDLE handle = WinDivertOpen("tcp", WINDIVERT_LAYER_NETWORK, priority, 0); //���͸� tcp��, WINDIVERT_LAYER_NETWORK=> ��Ʈ��ũ ���̾� �� 3�������� �����ϵ���,  priority�� 0���� �̶� ������ flag ���� ����Ʈ�� ���� ���� ������ �ٸ� �÷��׸� �����ϴ� ���̾ƴ� ����ڰ� ���Ƿ� ���� �� �ְ� ���ִ� flag�� ����
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
	

	while (true)
	{
		
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len)) //��Ŷ ���� ���� ���� ó�� RecvEx�ʹ� lpOverlapped parameter�� ���̰� ����.
		{
			cout << "warning: failed to read packet : "<<GetLastError()<<endl; //������ ���� ���� ���
			continue;
		}
		ip_header = (PWINDIVERT_IPHDR)packet;
		UINT originPacketLen = packet_len;

		int ip_headerLen = ip_header->HdrLength * 4;
		packet_len -= ip_headerLen; //������ ����� ���� ���� -



		if (ip_header->Protocol != IPPROTO_TCP)  //TCP��� Ÿ���� �ƴϸ� �ٽ� ��Ŷ ����
		{
			if (!WinDivertSend(handle, (PVOID)packet, originPacketLen, &addr, NULL)) //3��° ���ڴ� ��Ŷ�� ���̸� �Ѱ��ְ� 5��°�� ���� ���� ��Ŷ�� ���̸� ��ȯ���ִ� ����
			{
				cout << "WinDivertSend Error!!2" << endl;
				cout << GetLastError() << endl;
				continue;
			}
			continue;
		}
		PWINDIVERT_TCPHDR tcp_header = (PWINDIVERT_TCPHDR)(packet + ip_headerLen); //tcp��� ���� 

		int tcp_headerLen= tcp_header->HdrLength * 4;
		packet_len -= tcp_headerLen;
		
		if (packet_len <= 0)//data�κ��� ������
		{
			if (sendPacket(handle, (PVOID)packet, originPacketLen, &addr))
				continue;
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
		if (hostLen == 0) //Host �κ��� ã�� ��������
		{
			if (sendPacket(handle, (PVOID)packet, originPacketLen, &addr))
				continue;
			continue;//�ٽ� ��Ŷ ĸ��
		}
			
		uint8_t* hostInPacket = new uint8_t[hostLen+1]; //���̸�ŭ ���� �Ҵ�
		memcpy(hostInPacket, sHost, hostLen); // �ش� ���ڿ� ���� 
		hostInPacket[hostLen] = 0; //�� �߰�
		string domainInPacket = (char*)hostInPacket;
	
		if (domainInPacket.find("www") != string::npos) //���忡 www�� ������
		{
			domainInPacket = domainInPacket.substr(domainInPacket.find(".") + 1, domainInPacket.length()); //www�� �ڸ� 
			hostLen -= 4; //www. �� ���� ���̸�ŭ ���� 
			memcpy(hostInPacket, domainInPacket.c_str(), hostLen);
			hostInPacket[hostLen] = 0; //�� �߰�
		}


		bool isFind = false;

		if (!parse.retnIsFile()) //������ ������ ��, ���ڷ� �ּҸ� ������
		{
			if (strcmp((char*)hostInPacket, parse.retnHost()) == 0)
			{
				cout << "Host " << parse.retnHost() << " Blocked !!" << endl;
			}
			else { //�ش� ȣ��Ʈ�� �ƴ϶�� 
				if (sendPacket(handle, (PVOID)packet, originPacketLen, &addr))
					continue;
			}
		}
		else //������ ������  
		{
			int count = 0;
			

			cout <<"��Ŷ ȣ��Ʈ : "<<hostInPacket << endl;
			
			char* dp=domainInFile;//������ ������

			while ((fileLength - count)>hostLen) //������ ������ �������� host�� ���̺��� Ŭ������ 
			{
				count++;
			
				if (memcmp(dp, hostInPacket,hostLen) == 0) //�̶� hostLen�� null�� �������� ���� ��Ŷ�� �ִ� ���� len
				{
					cout << "Host : " << hostInPacket << " Blocked!! " << endl;
					isFind = true;

					/* rst ��Ŷ ����
					RstPacket rstPacket(packet);
					RstPacket* pRst = &rstPacket;

					addr.Direction = !addr.Direction; //��Ŷ�� ���� ���¸� �ٲ���

					WinDivertHelperCalcChecksums((PVOID)&pRst, sizeof(RstPacket), 0);
					if (!WinDivertSend(handle, (PVOID)&rstPacket, sizeof(RstPacket), &addr, NULL)) //send RST��Ŷ
					{
						cout << "WinDivertSend Error!!" << endl;
						cout << GetLastError() << endl;
						continue;
					}
					*/
					break; //Ž�����ʿ䰡 ����
				}
				else {
					dp++;
				}
			}
			

			if (!isFind) //host�� ã�� ���ߴٸ� ��, relay�� �ʿ��ϴٸ� 
			{

				if (sendPacket(handle, (PVOID)packet, originPacketLen, &addr))
					continue;
				isFind = false;
			}

		}

	}

	WinDivertClose(handle);
	File.close();
}

void fileOpen(ifstream & File, char* FileName)
{
	File.open(FileName, ios::binary); //���̳ʸ� ���� ����
	if (!File.is_open())
	{
		perror("File open");
		exit(1);
	}
}

bool sendPacket(HANDLE handle, PVOID packet, int len, WINDIVERT_ADDRESS * addr)
{
	if (!WinDivertSend(handle, packet, len, addr, NULL)) //3��° ���ڴ� ��Ŷ�� ���̸� �Ѱ��ְ� 5��°�� ���� ���� ��Ŷ�� ���̸� ��ȯ���ִ� ����
	{
		cout << "WinDivertSend Error!!" << endl;
		cout << GetLastError() << endl;
		return true;
	}

	return false;
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
