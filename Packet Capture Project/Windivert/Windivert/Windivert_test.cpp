#include <iostream>
#include "parse.h"
#include <fstream>
#include <WinSock2.h>
#include "windivert.h"
#include <dbnetlib.h>
#include <iomanip>

#define MAXBUF  0xFFFF

using namespace std;


//Windivert -f "파일명" 
//Windivert "주소이름"

//파일 비교시 ,을 구분자로 사용하여 떼내어야 함 

void printHexData(uint8_t* printArr, int length);
void fileOpen(ifstream & File, char* FileName);

int main(int argc, char* argv[])
{
	Parse parse(argc, argv);
	ifstream File;

	if (parse.retnIsFile()) //파일이 있으면
		fileOpen(File, parse.retnFileName());
	
	int16_t priority = 0; //우선순위를 0으로 설정
	HANDLE handle = WinDivertOpen("tcp", WINDIVERT_LAYER_NETWORK, priority, 0); //필터를 tcp로, WINDIVERT_LAYER_NETWORK=> 네트워크 레이어 즉 3계층에서 동작하도록,  priority를 0으로 이때 마지막 flag 값은 사이트에 나와 있지 않지만 다른 플래그를 설정하는 것이아닌 사용자가 임의로 정할 수 있게 해주는 flag로 추정
	if (handle == INVALID_HANDLE_VALUE) //설정이 되지 않았을 경우 
	{
		if (GetLastError() == ERROR_INVALID_PARAMETER) //에러의 값이 파라미터 즉, 필터가 잘못된경우
		{
			cout << "error: filter syntax error" << endl;
			exit(EXIT_FAILURE); //EXIT_FAILURE -> 1
		}
		cout << "error: failed to open the WinDivert device : " << GetLastError()<< endl;
		cout << "Please Check if your admin" << endl;
		exit(EXIT_FAILURE);
	}

	//큐의 크기와 시간 재정의
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_LEN, 8192)) //길이가 8192 즉 최댓 값이 아니면(기본 값 : 512) 설정 이때 설정에 실패했으면 false가 리턴
	{
		cout << "error: failed to set packet queue length : " << GetLastError() << endl;
		exit(EXIT_FAILURE);
	}
	if (!WinDivertSetParam(handle, WINDIVERT_PARAM_QUEUE_TIME, 2048))//이때 시간의 기본값은 512 단위는 miliseconds
	{
		cout << "error: failed to set packet queue time " << GetLastError() << endl;
		exit(EXIT_FAILURE);
	}

	/*받을 패킷에 다한 변수 선언*/
	uint8_t packet[MAXBUF];
	UINT packet_len; //uint-> unsigned int 
	WINDIVERT_ADDRESS addr;
	/* 프로토콜 헤더 정의*/
	PWINDIVERT_IPHDR ip_header; //PWINDIVERT_IPHDR 이것 자체가 포인터를 의미하는 헤더 
	
	UINT8 TCP = 6;//TCP의 Protocol ID 헤더에 정의된 부분이 있을 것 같지만 추후에 찾아서 수정

	while (true)
	{
		
		if (!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len)) //패킷 수신 여부 예외 처리 RecvEx와는 lpOverlapped parameter의 차이가 있음.
		{
			cout << "warning: failed to read packet : "<<GetLastError()<<endl; //에러에 대한 내용 출력
			continue;
		}
		ip_header = (PWINDIVERT_IPHDR)packet;
		UINT originPacketLen = packet_len;

		int ip_headerLen = ip_header->HdrLength * 4;
		packet_len -= ip_headerLen; //데이터 출력을 위해 길이 -

		if (ip_header->Protocol != TCP)  //TCP헤더 타입이 아니면 다시 패킷 수신
		{
			if (!WinDivertSend(handle, (PVOID)packet, originPacketLen, &addr, NULL)) //3번째 인자는 패킷의 길이를 넘겨주고 5번째는 실제 보낸 패킷의 길이를 반환해주는 인자
			{
				cout << "WinDivertSend Error!!2" << endl;
				cout << GetLastError() << endl;
				printHexData(packet, originPacketLen);
				cout << "Direction : " << (int)addr.Direction << endl; //out bound 0
				cout << "Interface : " << (int)addr.IfIdx << endl;
				UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
				UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
				printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u ",
					src_addr[0], src_addr[1], src_addr[2], src_addr[3],
					dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				cout << endl;
				continue;
			}
			continue;
		}
		PWINDIVERT_TCPHDR tcp_header = (PWINDIVERT_TCPHDR)(packet + ip_headerLen); //tcp헤더 참조 

		int tcp_headerLen= tcp_header->HdrLength * 4;
		packet_len -= tcp_headerLen;
		
		if (packet_len <= 0)//data부분이 없으면
		{
			if (!WinDivertSend(handle, (PVOID)packet, originPacketLen, &addr, NULL))
			{
				cout << "WinDivertSend Error!!3" << endl;
				cout << GetLastError() << endl;
				printHexData(packet, originPacketLen);
				cout << "Direction : " << (int)addr.Direction << endl; //out bound 0
				cout << "Interface : " << (int)addr.IfIdx << endl;
				UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
				UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
				printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u ",
					src_addr[0], src_addr[1], src_addr[2], src_addr[3],
					dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				cout << endl;
				continue;
			}
			continue; //패킷 다시 캡쳐
		}
			


	
		uint8_t *tcpData=(uint8_t*)((uint8_t*)tcp_header+ tcp_headerLen) ;//데이터 부분부터 참조 이때 (uint8_t*)tcp_header를 캐스팅 해주지않으면 주소의 값(tcp헤더)의 크기 20 의 배수만큼 headerLen이 더해져 이상한 위치 참조
		UINT32 *host;
		UINT32 HostValue=0x486f7374; //Host 
		uint8_t* sHost;//문자열의 시작 주소를 저장
		int hostLen = 0;
		while (packet_len-- > 3) //마지막 길이로 부터 3이전까지 참조
		{
			host = (UINT32*)tcpData;
			if (ntohl(*host) == HostValue) //Host의 위치를 찾으면 
			{
				uint8_t* tmp = (uint8_t*)host;
				
				while (*tmp++ != 0x20); //Host : test.gilgil.net에서 현재 포인터는 Host의 H를 가르키고 있으므로 Host의 시작 주소의 문자를 가르키게 함 

				sHost = tmp ; // 호스트의 시작 포인터 값을 저장 (아래에서 tcpData값을 변경하므로 저장해둠)
				tcpData = tmp; //데이터의 참조 위치를 호스트 시작 포인터 값으로 이동
				while (*tcpData!=0x0d&&*(tcpData+1)!=0x0a) //0d 0a 즉 \r \n을 찾을때까지 
				{
					tcpData++; //데이터의 참조 위치를 옮겨줌
					hostLen++; //호스트의 길이 체크
				}
				break;
			}
			else {
				tcpData++;
			}
		}

		uint8_t* hostInPacket = new uint8_t[hostLen+1]; //길이만큼 동적 할당
		memcpy(hostInPacket, sHost, hostLen); // 해당 문자열 복사 
		hostInPacket[hostLen] = 0; //널 추가
		
		char domain[70];//세계에서 가장 큰 도메인이 63글자
		bool isFind = false;
		if (!parse.retnIsFile()) //파일이 없으면 즉, 인자로 주소를 받으면
		{
			if (strcmp((char*)hostInPacket, parse.retnHost()) == 0)
			{
				cout << "Host " << parse.retnHost() << " Detected !!" << endl;
			}
			else { //해당 호스트가 아니라면 
				if (!WinDivertSend(handle, (PVOID)packet, originPacketLen, &addr, NULL))
				{
					cout << "WinDivertSend Error!!4" << endl;
					cout << GetLastError() << endl;
					printHexData(packet, originPacketLen);
					cout << "Direction : " << (int)addr.Direction << endl; //out bound 0
					cout << "Interface : " << (int)addr.IfIdx << endl;
					UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
					UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
					printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u ",
						src_addr[0], src_addr[1], src_addr[2], src_addr[3],
						dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
					cout << endl;
					continue;
				}
			}
		}
		else //파일이 있으면  
		{
			while (!File.eof())//파일의 끝일때 까지 
			{
				File.getline(domain, 70);
				//string tmp=domain;
				if (strcmp(domain, (char*)hostInPacket) == 0)
				{
					cout << "Host : "<<hostInPacket << "Detected!! " << endl;
					isFind = true;
				}
			}
		}

		if (isFind)
		{
			if (!WinDivertSend(handle, (PVOID)packet, originPacketLen, &addr, NULL))
			{
				cout << "WinDivertSend Error!!4" << endl;
				cout << GetLastError() << endl;
				printHexData(packet, originPacketLen);
				cout << "Direction : " << (int)addr.Direction << endl; //out bound 0
				cout << "Interface : " << (int)addr.IfIdx << endl;
				UINT8 *src_addr = (UINT8 *)&ip_header->SrcAddr;
				UINT8 *dst_addr = (UINT8 *)&ip_header->DstAddr;
				printf("ip.SrcAddr=%u.%u.%u.%u ip.DstAddr=%u.%u.%u.%u ",
					src_addr[0], src_addr[1], src_addr[2], src_addr[3],
					dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3]);
				cout << endl;
				continue;
			}
			isFind = false;
		}
}
	/*
	char tmp[100];

	while (!File.eof()) {

		File.getline(tmp,100);
		cout << tmp << endl;

	}
	*/

	WinDivertClose(handle);
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