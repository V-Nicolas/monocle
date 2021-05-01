/*
 *  monocle
 *  src/monocle.h
 *
 *  Author: Vilmain Nicolas
 *  Contact: nicolas.vilmain@gmail.com
 *
 *  This file is part of monocle.
 *
 *  monocle is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  monocle is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with monocle.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __MONOCLE_H__
#define __MONOCLE_H__

#include  "ostype.h"

#if !defined(__BSD) && !defined(__Linux)
# error "set macros __Linux or __BSD"
#endif /* not __Linux and not __BSD */

#include  <time.h>
#include  <fcntl.h>
#include  <errno.h>
#include  <stdio.h>
#include  <stdlib.h>
#include  <stdint.h>
#include  <string.h>
#include  <unistd.h>
#include  <stdarg.h>
#include  <signal.h>
#include  <sys/time.h>
#include  <sys/ioctl.h>
#include  <netinet/in.h>
#include  <arpa/inet.h>
#include  <sys/socket.h>
#ifdef __Linux
# include  <linux/if.h>
# include  <linux/if_ether.h>
# include  <linux/if_packet.h>
#elif defined (__BSD)
# include  <net/if.h>
# include  <net/if_dl.h>
# include  <net/bpf.h>
# include  <net/ethernet.h>
#endif /* not __Linux */
#include  <ifaddrs.h>
#include  "error.h"

#define  NO_SHOW_HDR     0x01
#define  MS_TIME         0x02
#define  VERBOSE         0x04
#define  PASSIV          0x08

#define  DATESIZE        25
#define  NAME_LEN        16
#define  MAC_SIZE        6
#define  IP4_SIZE        4
#define  PACKET_SIZE     65535
#define  ARP_SIZE        sizeof (struct arp_packet_s)
#define  BROADCAST_ADDR  "\xff\xff\xff\xff\xff\xff"
#define  NULL_MAC        "\x00\x00\x00\x00\x00\x00"

/* ARP opcode */
#define  ARP_OPCODE_REQUEST 1
#define  ARP_OPCODE_REPLY   2

/* mac utils */
#define PRINT_MAC_ADDRS(mac)				\
  mac[0] & 0xff, mac[1] & 0xff, mac[2] & 0xff,		\
  mac[3] & 0xff, mac[4] & 0xff, mac[5] & 0xff


/* error because strict aliasing !
   you need compiling with flags -fno-strict-aliasing for use
   this macro ... but replace by memcpy ... it's more easy
#define COPY_MAC(dst, src)					\
  (*(uint32_t *) dst)       =   (*(uint32_t *) src);		\
  (*(uint16_t *) (dst + 4)) =   (*(uint16_t *) (src + 4))
*/

#define  COPY_MAC(dst, src)    memcpy (dst, src, MAC_SIZE)
#define  CMP_MAC(mac1, mac2)   memcmp (mac1, mac2, MAC_SIZE)

/* IP utils */
#define  COPY_IP(dst, src)     memcpy (dst, src, IP4_SIZE)
#define  CMP_IP(ip1, ip2)      memcmp (ip1, ip2, IP4_SIZE)

/* protocol list */
enum
  {
#ifdef __Linux
    ETH_IP = ETH_P_IP,
    ETH_ARP = ETH_P_ARP,
#elif defined(__BSD)
    ETH_IP = ETHERTYPE_IP,
    ETH_ARP = ETHERTYPE_ARP,
#endif /* not __Linux */
  };

struct netconf_s
  {
    int nc_index;
    int nc_mtu;
    char nc_name[NAME_LEN];
    uint8_t nc_mac[MAC_SIZE];
    struct in_addr nc_ipv4;
  };

struct target_s
  {
    uint8_t ip[IP4_SIZE];
    uint8_t mac[MAC_SIZE];
    int usec_send;
    int usec_recv;
  };

struct pktstat_s
  {
    int ps_arp_query;
    int ps_arp_req;
    int ps_arp;
  };

struct monocle_s
  {
    int time;
    int max_packet;
    int nhost;
    int nrecv;
    int result;
    int sec_send;
    int usec_send;
    time_t start_time;
    uint8_t opt;
    FILE *file_oui;
    char *output_format;
    struct pktstat_s *stat;
    struct netconf_s nc;
    struct target_s **target;
  };
#define MONOCLE  struct monocle_s

struct ethsock_s
  {
    int fdsock;
#ifdef __Linux
    struct sockaddr_ll ll;
# define   SOCK_LL_SIZE   sizeof (struct sockaddr_ll)
#endif /* __Linux */
  };

struct arp_packet_s
  {
    uint8_t eth_dst[MAC_SIZE];
    uint8_t eth_src[MAC_SIZE];
    uint16_t eth_protocol;
    uint16_t arp_hrd;
    uint16_t arp_protocol;
    uint8_t arp_hln;
    uint8_t arp_pln;
    uint16_t arp_opcode;
    uint8_t arp_mac_src[MAC_SIZE];
    uint8_t arp_ip_src[IP4_SIZE];
    uint8_t arp_mac_dst[MAC_SIZE];
    uint8_t arp_ip_dst[IP4_SIZE];
  } __attribute__((packed));

void *  xcalloc (size_t size);
void *  xmalloc (size_t size);
int     get_netconf (struct netconf_s *nc, const char *name);
int     get_ethsock (struct ethsock_s *s, int index, const char *name);
int     ethsend (struct ethsock_s *s, void *packet, size_t size);
int     ethrecv(int fdsock, void *packet, MONOCLE *monocle);
void    open_file_oui (MONOCLE *monocle);
void    file_oui_search_mac_vendor (FILE *oui, uint8_t *mac);

char *program_name;
int debug;
char date[DATESIZE];
MONOCLE *gmono;

#endif /* not __MONOCLE_H__ */
