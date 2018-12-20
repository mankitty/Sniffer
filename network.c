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
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#define	MAXEPOLL	10240

#define DNSS 0x35

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
#if 0
unsigned short nf_portal_get_proto(struct ethhdr * skb,unsigned int *uiOffset)
{
	return 0;
}
#endif


void dns_resolve(struct udphdr *pstUdpHdr)
{
    unsigned int uiLoop;
    unsigned int uiIp = 0;
    unsigned int uiUrlLen = 0;
    unsigned int uiDnsLen = 0;
    unsigned char *pucPos = NULL;
    unsigned short usType = 0;
    unsigned char aucUrl[128] = {"\0"};
    
    struct iphdr *pstIpHdr = NULL;
    NF_PORTAL_DNS_HDR_T *pstDnsHdr = NULL;

    if (NULL == pstUdpHdr)
    {
        err_msg("skb is null,or pstUdpHdr is null,return");
        return;
    }
    pstDnsHdr = (NF_PORTAL_DNS_HDR_T *)((unsigned char *)pstUdpHdr + UDP_HLEN);
    if (NULL == pstDnsHdr)
    {
        err_msg("pstDnsHdr is null,return");
        return;  
    }
    
    uiDnsLen = ntohs(pstUdpHdr->len) - UDP_HLEN;
    pstIpHdr = (struct iphdr *)((unsigned char *)pstUdpHdr - IP_HLEN);

    if (uiDnsLen < DNS_HLEN)
    {
        err_msg("dns total len is less than dns head len");
        return;
    }
    
    #if defined (LITTLE_ENDIAN)
    if (ROOT_DNS_SERVER_FLAGS != ntohs(pstDnsHdr->usFlags) && AUTHORITY_DNS_SERVER_FLAGS != ntohs(pstDnsHdr->usFlags))
    {
        err_msg("flags do not match");
        return;
    }
    #else
    if ((pstDnsHdr->QR != DNS_FLAG_QR_R) || (pstDnsHdr->opcode != DNS_FLAG_OPCODE_S) || (pstDnsHdr->TC != DNS_FLAG_TC_NO) || (pstDnsHdr->rcode != DNS_FLAG_RCODE_OK))
    {
        err_msg("flags do not match");
        return;
    }
    #endif
    
    pucPos = (unsigned char *)((unsigned char *)pstDnsHdr + DNS_HLEN);
    uiDnsLen = uiDnsLen - DNS_HLEN;

    for (uiLoop = 0;uiLoop < ntohs(pstDnsHdr->usQuestions); uiLoop++)
    {
        while(0 != (*pucPos))
        {
            if(uiUrlLen + *pucPos + 1 >= URL_MAX_SIZE)
            {
                //NF_PORTAL_LOG(NF_PORTAL_LOG_WARNING,"too long domain,return\n");
                //print_packet(NF_PORTAL_LOG_WARNING,"Print ip packet",(UINT8 *)pstIpHdr, ntohs(pstIpHdr->tot_len));
                return;
            }

            if(uiDnsLen < *pucPos + 1)
            {
                //NF_PORTAL_LOG(NF_PORTAL_LOG_WARNING,"dns packet is truncated1,return\n");
                //print_packet(NF_PORTAL_LOG_WARNING,"Print ip packet",(UINT8 *)pstIpHdr, ntohs(pstIpHdr->tot_len));
                return;
            }

            memcpy((aucUrl + uiUrlLen),(pucPos + 1),*pucPos);
            uiUrlLen += (*pucPos);
            aucUrl[uiUrlLen] = '.';
            uiUrlLen++;

            pucPos +=(*pucPos + 1);
            uiDnsLen -=(*pucPos + 1);
        }
        aucUrl[uiUrlLen - 1] = '\0';

        if(uiDnsLen < 5)/*1+2+2*/
        {
            //NF_PORTAL_LOG(NF_PORTAL_LOG_WARNING,"dns packet is truncated2,return\n");
            //print_packet(NF_PORTAL_LOG_WARNING,"Print ip packet",(UINT8 *)pstIpHdr, ntohs(pstIpHdr->tot_len));
            return;
        }
        pucPos += 5; 
        uiDnsLen -= 5;
        uiUrlLen = 0;
        err_msg("url=%s\n",aucUrl);
    }
    for(uiLoop = 0; uiLoop < ntohs(pstDnsHdr->usAnswerRRS); uiLoop++)
    {
        if(uiDnsLen < 10)/*2+2+2+4*/
        {
            //NF_PORTAL_LOG(NF_PORTAL_LOG_WARNING,"dns packet is truncated3,return\n");
            //print_packet(NF_PORTAL_LOG_WARNING,"Print ip packet",(UINT8 *)pstIpHdr, ntohs(pstIpHdr->tot_len));
            return;
        }
        pucPos += 2; /*????*/
        uiDnsLen -= 2;
        usType = ntohs(*(unsigned short *)pucPos);
        pucPos += 8; /*2+2+4*/
        uiDnsLen -= 8;
        if (usType == DNS_ANSWER_TYPE_A)
        {
            if(uiDnsLen < 6)
            {
                //NF_PORTAL_LOG(NF_PORTAL_LOG_WARNING,"dns packet is truncated4,return\n");
                //print_packet(NF_PORTAL_LOG_WARNING,"Print ip packet",(UINT8 *)pstIpHdr, ntohs(pstIpHdr->tot_len));
                return;
            }
            pucPos += 2;
            uiDnsLen -= 2;
            uiIp = ntohl(*(unsigned int *)pucPos);
            err_msg("IP="IP_FMT"\n",IP_ARG(&uiIp));
            pucPos += 4;/*data len*/
            uiDnsLen -= 4;
        }
        else
        {
            if(uiDnsLen < ntohs(*(unsigned short *)pucPos))
            {
                //NF_PORTAL_LOG(NF_PORTAL_LOG_DEBUG,"dns packet is truncated5,return\n");
                return;
            }
            pucPos += (ntohs(*(unsigned short *)pucPos) + 2);
        }
    }
}

int nf_portal_is_dns_frame(unsigned short usPort)
{
    if (usPort == DNSS)
    {
        return 1;
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
        
		unsigned int uiOffset = 0;
        struct iphdr *pstIpHdr = NULL;
        struct udphdr *pstUdpHdr = NULL;
        
		bzero(recvBuf,sizeof(recvBuf));
		int n = recvfrom(socket, recvBuf, sizeof(recvBuf), 0, NULL, NULL);
		if (n <=0)
        {
            err_msg("recvfrom is error");
            return;
        }
        struct ethhdr *skb = (struct ethhdr *)recvBuf;
        if (NULL == skb)
        {
            err_msg("pstEthHdr is NULL");
            continue;
        }
        pstIpHdr = (struct iphdr *)((unsigned char *)skb + ETH_HLEN + uiOffset);
        
        if (NULL == pstIpHdr)
        {
            err_msg("ip header is null,but accept yet");
            continue;
        }
        
        if (pstIpHdr->protocol == IPPROTO_UDP)
        {
            pstUdpHdr = (struct udphdr *)((unsigned char *)(pstIpHdr) + (pstIpHdr->ihl)*4);
            if (NULL == pstUdpHdr)
            {
                err_msg("udp header is null,but accept yet\n");
                continue;
            }

            /*解析DNS报文获取URL和IP地址*/
            if (nf_portal_is_dns_frame(ntohs(pstUdpHdr->source)))
            {
                if((ntohs(pstIpHdr->tot_len) - (pstIpHdr->ihl)*4) >= ntohs(pstUdpHdr->len))
                    dns_resolve(pstUdpHdr);
            }
        }
        
        //printf("Dest MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",pstEthHdr->h_dest[0],pstEthHdr->h_dest[1],pstEthHdr->h_dest[2],pstEthHdr->h_dest[3],pstEthHdr->h_dest[4],pstEthHdr->h_dest[5]);
        //printf("Source MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",pstEthHdr->h_source[0],pstEthHdr->h_source[1],pstEthHdr->h_source[2],pstEthHdr->h_source[3],pstEthHdr->h_source[4],pstEthHdr->h_source[5]);
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
