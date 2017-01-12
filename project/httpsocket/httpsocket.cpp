#include <winsock2.h>
#include <windows.h>
#include <iostream>

#pragma warning(disable:4996)


using namespace std;

int main(int argc, char* argv[]) //����� �Ű� ������ �Է� ����
{



	WSADATA wsaData; //�Ʒ��� ���� ����ü�� ���� 
	/*
	typedef struct WSAData {
		WORD                wVersion;
		// WS2_32.dll���� �ε�� �������� ������ ����
		WORD                wHighVersion;
		// �ε��� DLL�� �����ϴ� �������� ������ ���� ����.
		//    (�Ϲ������� wVersion���ڿ� ����)
		char                 szDescription[WSADESCRIPTION_LEN + 1];
		// NULL�� ������ �ƽ�Ű ��Ʈ�� ��.
		// (����� WS2_32.dll���� ���Ͽ� ���õ� ���� ���ڿ��� ī��)
		char                 szSystemStatus[WSASYS_STATUS_LEN + 1];
		// NULL�� ������ �ƽ�Ű ��Ʈ�� ��.
		// (�ý����� ���� ���¸� �˼� �ֵ��� ���ش�.)
		unsigned short    iMaxSockets;
		// ���ø����̼ǿ��� ����� ������ �ִ� ���� ������ �ִ� ���
		// (version 2���ʹ� ���õȴ�.)
		unsigned short    iMaxUdpDg;
		// ���ø����̼��� ������ �� �ִ� �����ͱ׷� �ִ� ũ�⸦ ����
		// (version 2���ʹ� ���õȴ�.)
		char       FAR     *lpVendorInfo;
		// (version 2���ʹ� ���õȴ�.)
	}WSADATA, FAR * LPWSADATA;
	*/
	
	if (argc != 3) //���޵� ���� 3���� �ƴϸ� ��, ��ɾ� + ������ + ��Ʈ�� �ƴϸ�
	{
		cout << "���� : httpsocket <������> <��Ʈ>" << endl; //���� ��� �� 
		exit(1); //���� 
	}
	
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)  //���α׷����� �䱸�ϴ� ������ ������ ������ �˸��� �ش� ������ �����ϴ� ���̺귯���� �ʱ�ȭ �۾��� ����
	{												//���ڰ�(�Ű�����) 1->����� ���� ������ 2.2 �̸� 0x0202�� �����ؾ��ϴµ� ���ŷο�Ƿ� ������������ ������ִ� makeword�� ���
		cout << "WSAStartup failed.\n";				//���ڰ�(�Ű�����) 2->wsadata����ü ������ �ּ� ���� ���ڷ� ���� �ؾ��Ѵ�.�Լ� ȣ�� �� �ش� ������ �ʱ�ȭ�� ���̺귯�� ������ ä����
		return 1;
	}
	SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//���������� ��ũ���� ���� �����̸� �ڵ��� ��ȯ 
																//AF_INET -> IPv4 SOCK_STREAM -> ���� ���� IPPROTO_TCP -> TCPŸ��
	struct hostent *host;	//�������̸����� IP�ּҸ� ��� ���� ����ü ������ �Ʒ��� ����
	/*
	struct hostent
	{
		char *h_name;				//���� ������ �̸��� ����
		char **h_aliases;			//�ϳ��� IP �� �� �̻��� �������� �����ϴ� ���� �����ϹǷ� ���� ������ �̿ܿ� �ش� �������� ������ �� �ִ� �ٸ� ������ �̸��� ����
		int h_addtype;				//gethostbyname�� IPv4�Ӹ��ƾƴ϶� IPv6�� �����ϱ� ������ �ּ� ü�� ������ ��ȯ ex)IPv4 -> AF_INET
		int h_length;				//��ȯ�� IP�ּ��� ũ�� (IPv4��� 4����Ʈ=> 32bit)
		char **h_addr_list;			//IP�ּҰ� ������ ���·� ��ȯ
	}
	*/
	host = gethostbyname(argv[1]);//�־��� ȣ��Ʈ name(������)�� �����ϴ�  hostentŸ���� ����ü�� ��ȯ
	if (!host) //������ �߻��� ��� NULL�����͸� ��ȯ
	{
		cout << "gethostbyname() Error!" << endl;
		exit(1);
	}

	SOCKADDR_IN SockAddr;							//IPv4�ּ� ü�迡�� ����ϴ� ����ü 
	SockAddr.sin_port = htons(atoi(argv[2]));		//���ڿ� �������� ���� ��Ʈ�� int�������� �ٲپ� big endiasn���(���� ����Ʈ���� ��� �ϴ� ���)���� ���� 
	SockAddr.sin_family = AF_INET;					//IPv4ü�� 
	SockAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr); //h_addr_list[0]�� ����� ���� IP�ּ� ���� sockAddr����ü�� �ּҿ� �ش��ϴ� �׸� ����
	
	cout << "���� �� ..." << endl;
	//connect(Ŭ���̾�Ʈ ������ ���� �ڵ鷯(��ũ����),�����û�� ���� ���� �ּ������� ���� ����ü ���� ������,�����Ͱ� ����Ű�� �ּ� ���� ����ü ������ ũ��)
	if (connect(Socket, (SOCKADDR*)(&SockAddr), sizeof(SockAddr)) != 0) //������ 0 ��ȯ ���н� -1 ��ȯ
	{
		cout << "Could not connect";
		system("pause");
		return 1;
	}
	cout << "���� ����" << endl;

	string sendMe= "GET / HTTP/1.1\r\nHost: ";	
	sendMe.append(argv[1]);
	sendMe.append("\r\nConnection: close\r\n\r\n");
	//request������ string�� ���� �Ͽ� request�� �ۼ� 
	send(Socket, sendMe.c_str(), sendMe.length(), 0); //request�޼��� ���� 

	char buffer[1024];

	int nDataLength;
																				
	while ((nDataLength = recv(Socket, buffer, sizeof(buffer),0)) > 0) //���� ������ ������ ����Ʈ �� ��ȯ ���н� -1 
	{
		int i = 0;
																							 //(unsigned char)�� ���� ����http://mwultong.blogspot.com/2007/08/unsigned-char-char-c-8.html
																							 //(unsigned char)�� ���� ���� https://github.com/EQEmu/Server/issues/396 
		while (buffer[i] == '\n' || buffer[i] == '\r' || isprint((unsigned char)buffer[i]))  //Ž���� char���� �����̸�
		{
			cout << buffer[i];//���
			i++;
			if (i > nDataLength)//i�� ������ ������ ���� ũ�ٸ� 
			{
				break;//while�� Ż�� 
			}
		}

	}
	closesocket(Socket); //���� ����
	WSACleanup(); //WSA���� 

	cout << endl;

	return 0;
}



//�ҽ��ڵ� ���� : http://nine01223.tistory.com/270
