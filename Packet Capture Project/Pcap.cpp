#include <iostream>
#include <pcap.h>
#include <sys/socket.h>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <cstdio>

using namespace std;

#define PROMISCUOUS 1 //Get every packet from Ethernet 
#define NONPROMISCUOUS 0 //Get only mine from Ethernet 

struct ip *iph; //Struct of IP
struct tcphdr *tcph; //Struct of TCP


void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);

void printMac(u_int8_t *addr);

int main(int argc, char* argv[]) //Device , Filter 
{
	if(argc!=3)
	{
			cout<<"Usage : Pcap [Device Name] [\"Filter\"]"<<endl;
			cout<<"You can fine filter rules at \"www.winpcap.org/docs/docs_40_2/html/group_language.html\""<<endl;
			exit(1);
	}

	char * device = argv[1];
	int ret;	
	char* netAddress;
	char* netMask;
	bpf_u_int32 netp; //IP
	bpf_u_int32 maskp; //Subnet Mask
	char errBuf[PCAP_ERRBUF_SIZE];
	struct in_addr addr;//Struct to save IPv4
	/*
	struct in_addr
	{
			u_long s_addr;
	}
	*/
	cout<<"Device :"<<device<<endl;
	if(ret = pcap_lookupnet(device,&netp,&maskp,errBuf) <0) //Get Network , Subnet mask about Device
	{														//error => return -1 & error content => errBuf
			perror(errBuf);									//error => print errBuf & exit
			exit(1);
	}
	
	addr.s_addr = netp;
	if((netAddress = inet_ntoa(addr))==NULL)//inet_ntoa => convert ulong type to Dotted-Decimal Notation 
	{
		perror("inet_ntoa");
		exit(1);
	}
	cout<<"Network Address : "<< netAddress <<endl;

	addr.s_addr = maskp;
	netMask = inet_ntoa(addr);//Subnet Mask convert

	cout<<"Subnet Mask : "<<netMask<<endl;

	pcap_t *pcd; //Packet capture descriptor 


	//BUFSIZ is a optimum size (defined in csdio)
	//Get packet capture descriptor from Device
	if((pcd = pcap_open_live(device,BUFSIZ, NONPROMISCUOUS , -1, errBuf))==NULL)
	{
			perror(errBuf);
			exit(1);
	}
	

	struct bpf_program fp;

	
	if(pcap_compile(pcd, &fp, argv[2] , 0, netp)==-1) //Set fp by filter rule(argv[2])
	{
			cout<<"Setfilter error!!!"<<endl;
			exit(1);
	}

	if(pcap_setfilter(pcd, &fp) == -1) //apply packet filter 
	{
			cout<<"Setfilter error"<<endl;
			exit(1);
	}


	pcap_loop(pcd, 0, callback, NULL); //count 1 -> 0 infinity loop

	

	return 0;

}



//packet => recevied pakcet 
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{

	struct ether_header *ep;
	unsigned short ether_type;
	int length=pkthdr->len;
	/* ehternet header */
	/*
	struct ehter_header
	{
			u_int8_t ether_dhost[ETH_ALEN];
			u_int8_t ether_shost[ETH_ALEN];
			u_int16_t ehter_type;
	}
			
	*/


	ep = (struct ether_header *)packet; //Save Ethernet Header
	cout<<"Information of Ehernet"<<endl;
	cout<<"Src Mac Address : ";
	printMac(ep->ether_shost);
	
	cout<<"Dest Mak Address : ";
	printMac(ep->ether_dhost);


	cout<<endl<<endl;



	
	ether_type = ntohs(ep->ether_type);// ntohs(network to host short)
									   // network => little endian 
									  


	if(ether_type == ETHERTYPE_IP)	//next protocol is IP(0x0800) defined in netinet->if_ether 
	{	

		packet += sizeof(struct ether_header);//To bring IP header
		

		iph = (struct ip *)packet;
		cout<<"Information of IP"<<endl;
		cout<<"Src IP Address : "<<inet_ntoa(iph->ip_src)<<endl;
		cout<<"Dest IP Address : "<<inet_ntoa(iph->ip_dst)<<endl;
		cout<<endl<<endl;

		if(iph->ip_p== IPPROTO_TCP) //next protocol is TCP
		{
			packet = packet + iph->ip_hl * 4;
			tcph =(struct tcphdr *)packet;					 //TCP Header
															 //iph->ip_hl => Header length
															 //ip_hl is word so ip_hl * 4
															 //linux word => 4byte 
			cout<<"Informaiton of TCP"<<endl;
			cout<<"Src Port : "<<ntohs(tcph->source)<<endl;
			cout<<"Dst Port : "<<ntohs(tcph->dest)<<endl;
			cout<<endl<<endl;

			packet += sizeof(struct tcphdr); //To print Data Section 
		}


		for(int i=0; i<length;i++) //print data
		{
				if(i%16==0)
						cout<<endl;
				printf("%02x", *packet++);
		}

		cout<<endl<<endl;
	}else{
			cout<<"This Packet is not IP Packet"<<endl;
	}

}



void printMac(u_int8_t *addr)
{
		
	int sizeOfMac=6;//mac address => 48bit
					//mac use hexadecimal number
					//Ex) AB:CD:EF:GH:YJ:KL
					//hexadecimal number use 4bit per 1 num
					//0 0 0 0 => 0
					//1 1 1 1 => F => 15

	for(int i=0; i<sizeOfMac;i++)
	{
			printf("%02x",addr[i]);
			if(i!=sizeOfMac-1)
					printf(":");

	}


	cout<<endl;
}

/************************Information***************************/
//Ethernet & IP Header has a next protocol Info.
//Ethernet => ether_type IP => ip_p 
//***********************Flow chart****************************
//pcap_lookupnet => Get a Device name & Net & Subnet 
//pcap_open_live()=> Make a PCD(Packet Capture Descriptor)
//pcap_compile() //Set fp by filter rule
//pcap_setfilter() //apply packet filter 
//pcap_loop(); //callback a Function by PCD 
//Function







