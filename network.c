#include <stdio.h>
#include <errno.h>
#include <sys/un.h>
#include <stdlib.h>
#include <net/if.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <syslog.h>
#include <linux/ip.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include<linux/if_ether.h>
#include "sniffer_main.h"

#define	MAXEPOLL	10240

int creat_socket()
{
	int sockfd = -1;
	
	sockfd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if (-1 == sockfd)
		err_sys("create RAW socket failed !!!");
	
	return sockfd;
}

int set_promiscuous_mode(int socket)
{
	struct ifreq req;
	
	strncpy(req.ifr_name, "br0", IFNAMSIZ);
	if(-1 == ioctl(socket, SIOCGIFINDEX, &req))
	{
		close(socket);
		err_sys("ioctl SIOCGIFINDEX failed !!!");
	}

	req.ifr_flags |= IFF_PROMISC;
	if(-1 == ioctl(socket, SIOCSIFFLAGS, &req))
	{
		close(socket);
		err_sys("ioctl SIOCSIFINDEX failed !!!");
	}
	
	return 0;
}

void handle(int socket)
{
	char recvBuf[1024 * 8];
	while(1)
	{
		/**
		 *	struct ethhdr
		 *	{
    	 *		unsigned char h_dest[ETH_ALEN]; //目的MAC地址
    	 *		unsigned char h_source[ETH_ALEN]; //源MAC地址
    	 *		__u16 h_proto; //网络层所使用的协议类型
		 *	}__attribute__((packed))
		**/
		
		int n = recvfrom(socket, recvBuf, sizeof(recvBuf), 0, NULL, NULL);
		if (n > 0)
		{
			struct ethhdr *pstEthHdr = (struct ethhdr *)recvBuf;
			if (NULL == pstEthHdr)
			{
				err_msg("pstEthHdr is NULL");
				continue;
			}
			
			switch(pstEthHdr->h_proto)
			{
				case ETH_P_IP:
					break;
				case ETH_P_ARP:
					break;
				default:
					break;
			}
			printf("Dest MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",pstEthHdr->h_dest[0],pstEthHdr->h_dest[1],pstEthHdr->h_dest[2],pstEthHdr->h_dest[3],pstEthHdr->h_dest[4],pstEthHdr->h_dest[5]);
			printf("Source MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",pstEthHdr->h_source[0],pstEthHdr->h_source[1],pstEthHdr->h_source[2],pstEthHdr->h_source[3],pstEthHdr->h_source[4],pstEthHdr->h_source[5]);
		}
	}
}

int main_loop()
{	
	int sockfd = creat_socket();
	set_promiscuous_mode(sockfd);
	handle(sockfd);
	
	close(sockfd);
	
	return 0;
}