#ifndef _SNIFFER_MAIN_
#define _SNIFFER_MAIN_

#include <stdio.h>
#include <stdarg.h>

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN
#endif
#define MAXLINE 4096

#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define IP_HLEN 20      /*ip header length*/
#define UDP_HLEN 8      /*udp header length*/
#define TCP_HLEN 20     /*tcp header length*/
#define DNS_HLEN 12     /*dns header length*/
#define VLAN_HLEN 4

#define TRUE   1
#define FALSE  0
#define DNSS 0x35
#define URL_MAX_SIZE 128

#if defined (LITTLE_ENDIAN)
#define ROOT_DNS_SERVER_FLAGS 0x8180
#define AUTHORITY_DNS_SERVER_FLAGS 0x8580
#else
#define DNS_FLAG_QR_R 1
#define DNS_FLAG_OPCODE_S 0
#define DNS_FLAG_TC_NO 0
#define DNS_FLAG_RCODE_OK 0
#endif

#define DNS_ANSWER_TYPE_A 0x0001

#ifndef MAC_FMT
#define MAC_FMT     "%02x:%02x:%02x:%02x:%02x:%02x"
#endif
#ifndef MAC_ARG
#define MAC_ARG(x) ((unsigned char *)(x))[0],((unsigned char *)(x))[1],((unsigned char *)(x))[2],((unsigned char *)(x))[3],((unsigned char *)(x))[4],((unsigned char *)(x))[5]
#endif
#ifndef IP_FMT
#define IP_FMT      "%u.%u.%u.%u"
#endif
#ifndef IP_ARG
#define IP_ARG(x) ((unsigned char *)(x))[0], ((unsigned char *)(x))[1], ((unsigned char *)(x))[2], ((unsigned char *)(x))[3]
#endif

typedef struct
{
    unsigned short usTransactionId;
    #if defined (LITTLE_ENDIAN)
    unsigned short usFlags;
    #else
    unsigned short QR:1,
                opcode:4,
                AA:1,
                TC:1,
                RD:1,
                RA:1,
                zero:3,
                rcode:4;
    #endif
    
    unsigned short usQuestions;
    unsigned short usAnswerRRS;
    unsigned short usAuthorityRRS;
    unsigned short usAdditionalRRS;
}__attribute__((packed)) NF_PORTAL_DNS_HDR_T;


extern int main_loop();

extern void err_ret(const char *fmt, ...);
extern void err_sys(const char *fmt, ...);
extern void err_dump(const char *fmt, ...);
extern void err_msg(const char *fmt, ...);
extern void err_quit(const char *fmt, ...);
extern void	err_doit(int, const char *, va_list);

#endif