#include "getmyinfo.h"
#include "net/if.h"
#include "cstring"
#include <sys/ioctl.h>
#include <unistd.h>
#include <net/ethernet.h>

void getMyIP(char *device,uint32_t* my_IP)
{
    int fd;
    struct ifreq ifr;

    fd=socket(AF_INET,SOCK_DGRAM,0);


    ifr.ifr_ifru.ifru_addr.sa_family=AF_INET; //input type
    strcpy(ifr.ifr_ifrn.ifrn_name,device); // input device name

    ioctl(fd,SIOCGIFADDR,&ifr); //SIOCGIFADDR -> Get Protocol Address
    close(fd);
    memcpy(my_IP,ifr.ifr_ifru.ifru_addr.sa_data+2,sizeof(struct sockaddr));
}

void getMyhaddr(char* device,u_int8_t* my_MAC)
{

    int fd;
    struct ifreq ifr;

    fd=socket(AF_UNIX,SOCK_DGRAM,0);

    if(fd<0)
    {
        perror("socket error!!");
        exit(1);
    }
    strcpy(ifr.ifr_ifrn.ifrn_name,device); // input device name

    if(ioctl(fd,SIOCGIFHWADDR,&ifr)<0) //SIOCGIFHWADDR -> Get MAC Address
    {
        perror("ioctl :");
        exit(1);
    }
    close(fd);

    memcpy(my_MAC,ifr.ifr_ifru.ifru_hwaddr.sa_data,ETHER_ADDR_LEN);

}
