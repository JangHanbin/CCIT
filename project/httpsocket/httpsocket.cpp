#include <winsock2.h>
#include <windows.h>
#include <iostream>

#pragma warning(disable:4996)


using namespace std;

int main(int argc, char* argv[]) //실행시 매개 변수를 입력 받음
{



	WSADATA wsaData; //아래와 같은 구조체의 선언 
	/*
	typedef struct WSAData {
		WORD                wVersion;
		// WS2_32.dll에서 로드된 윈도우즈 소켓의 버전
		WORD                wHighVersion;
		// 로드한 DLL이 지원하는 윈도우즈 소켓의 상위 버전.
		//    (일반적으로 wVersion인자와 동일)
		char                 szDescription[WSADESCRIPTION_LEN + 1];
		// NULL로 끝나는 아스키 스트링 값.
		// (적재된 WS2_32.dll에서 소켓에 관련된 설명 문자열을 카피)
		char                 szSystemStatus[WSASYS_STATUS_LEN + 1];
		// NULL로 끝나는 아스키 스트링 값.
		// (시스템의 각종 상태를 알수 있도록 해준다.)
		unsigned short    iMaxSockets;
		// 어플리케이션에서 사용할 소켓의 최대 수를 리턴해 주는 멤버
		// (version 2부터는 무시된다.)
		unsigned short    iMaxUdpDg;
		// 어플리케이션이 전송할 수 있는 데이터그램 최대 크기를 리턴
		// (version 2부터는 무시된다.)
		char       FAR     *lpVendorInfo;
		// (version 2부터는 무시된다.)
	}WSADATA, FAR * LPWSADATA;
	*/
	
	if (argc != 3) //전달된 값이 3개가 아니면 즉, 명령어 + 도메인 + 포트가 아니면
	{
		cout << "사용법 : httpsocket <도메인> <포트>" << endl; //사용법 출력 후 
		exit(1); //종료 
	}
	
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)  //프로그램에서 요구하는 윈도우 소켓의 버전을 알리고 해당 버전을 지원하는 라이브러리의 초기화 작업을 진행
	{												//인자값(매개변수) 1->사용할 소켓 버전이 2.2 이면 0x0202를 전달해야하는데 번거로우므로 워드형식으로 만들어주는 makeword를 사용
		cout << "WSAStartup failed.\n";				//인자값(매개변수) 2->wsadata구조체 변수의 주소 값을 인자로 전달 해야한다.함수 호출 후 해당 변수에 초기화된 라이브러리 정보가 채워짐
		return 1;
	}
	SOCKET Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//리눅스에서 디스크립터 같은 존재이며 핸들을 반환 
																//AF_INET -> IPv4 SOCK_STREAM -> 연결 지향 IPPROTO_TCP -> TCP타입
	struct hostent *host;	//도메인이름으로 IP주소를 얻기 위한 구조체 형식은 아래와 같음
	/*
	struct hostent
	{
		char *h_name;				//공식 도메인 이름이 저장
		char **h_aliases;			//하나의 IP 에 둘 이상의 도메인을 소유하는 것이 가능하므로 공식 도메인 이외에 해당 페이지를 접속할 수 있는 다른 도메인 이름을 지정
		int h_addtype;				//gethostbyname는 IPv4뿐만아아니라 IPv6도 지원하기 때문에 주소 체계 정보를 반환 ex)IPv4 -> AF_INET
		int h_length;				//반환된 IP주소의 크기 (IPv4경우 4바이트=> 32bit)
		char **h_addr_list;			//IP주소가 정수의 형태로 반환
	}
	*/
	host = gethostbyname(argv[1]);//주어진 호스트 name(도메인)에 상응하는  hostent타입의 구조체를 반환
	if (!host) //에러가 발생한 경우 NULL포인터를 반환
	{
		cout << "gethostbyname() Error!" << endl;
		exit(1);
	}

	SOCKADDR_IN SockAddr;							//IPv4주소 체계에서 사용하는 구조체 
	SockAddr.sin_port = htons(atoi(argv[2]));		//문자열 형식으로 받은 포트를 int형식으로 바꾸어 big endiasn방식(상위 바이트부터 기록 하는 방식)으로 저장 
	SockAddr.sin_family = AF_INET;					//IPv4체계 
	SockAddr.sin_addr.s_addr = *((unsigned long*)host->h_addr); //h_addr_list[0]에 저장된 실제 IP주소 값을 sockAddr구조체의 주소에 해당하는 항목에 저장
	
	cout << "연결 중 ..." << endl;
	//connect(클라이언트 소켓의 파일 핸들러(디스크립터),연결요청을 보낼 서버 주소정보를 지닌 구조체 변수 포인터,포인터가 가르키는 주소 정보 구조체 변수의 크기)
	if (connect(Socket, (SOCKADDR*)(&SockAddr), sizeof(SockAddr)) != 0) //성공시 0 반환 실패시 -1 반환
	{
		cout << "Could not connect";
		system("pause");
		return 1;
	}
	cout << "연결 성공" << endl;

	string sendMe= "GET / HTTP/1.1\r\nHost: ";	
	sendMe.append(argv[1]);
	sendMe.append("\r\nConnection: close\r\n\r\n");
	//request형식을 string에 저장 하여 request문 작성 
	send(Socket, sendMe.c_str(), sendMe.length(), 0); //request메세지 전송 

	char buffer[1024];

	int nDataLength;
																				
	while ((nDataLength = recv(Socket, buffer, sizeof(buffer),0)) > 0) //수신 성공시 수신한 바이트 수 반환 실패시 -1 
	{
		int i = 0;
																							 //(unsigned char)에 대한 참조http://mwultong.blogspot.com/2007/08/unsigned-char-char-c-8.html
																							 //(unsigned char)에 대한 참조 https://github.com/EQEmu/Server/issues/396 
		while (buffer[i] == '\n' || buffer[i] == '\r' || isprint((unsigned char)buffer[i]))  //탐색한 char형이 문자이면
		{
			cout << buffer[i];//출력
			i++;
			if (i > nDataLength)//i가 버퍼의 사이즈 보다 크다면 
			{
				break;//while문 탈출 
			}
		}

	}
	closesocket(Socket); //소켓 종료
	WSACleanup(); //WSA종료 

	cout << endl;

	return 0;
}



//소스코드 참고 : http://nine01223.tistory.com/270
