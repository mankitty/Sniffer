#ifndef _unp_ifi_h
#define _unp_ifi_h

#include <stdio.h>
#include <errno.h>
#include <sys/un.h>
#include <stdlib.h>
#include <net/if.h>
#include <string.h>
#include <stdarg.h>
#include <syslog.h>
#include <linux/ip.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include<linux/if_ether.h>

#define VLAN_HLEN 4
#define MAXLINE         4096    /* max text line length */

struct vlanhdr{
        unsigned short vlan;
        unsigned short h_proto;
} __attribute__((packed));

#endif
