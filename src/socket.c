/*
 *  monocle
 *  src/socket.c
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

#include  "monocle.h"

static int   recv_timeout (int fd, MONOCLE *monocle);
static int   xselect (int fd, fd_set *rd, struct timeval *tv);
#ifdef __BSD
static int    get_bpf (const char *name);
static int    conf_bpf (int fd, const char *device_name);
#endif /* __BSD */
static int    xread (int fd, void *buf, size_t size);

int
get_ethsock (struct ethsock_s *s, int index, const char *name)
{

#ifdef __Linux
  (void) name;
  s->fdsock = socket (AF_PACKET, SOCK_RAW, ETH_ARP);
  if (s->fdsock == -1)
    {
      DEBUG (3);
      error ("socket: %s\n", strerror (errno));
      return -1;
    }
  memset (&s->ll, 0, SOCK_LL_SIZE);
  s->ll.sll_family = AF_PACKET;
  s->ll.sll_protocol = htons (ETH_ARP);
  s->ll.sll_ifindex = index;
  if (bind (s->fdsock, (struct sockaddr *) &s->ll, SOCK_LL_SIZE) == -1)
    {
      DEBUG (2);
      error ("bind: %s\n", strerror (errno));
      close (s->fdsock);
      return -1;
    }

#elif defined(__BSD)
  (void) index;
  s->fdsock = get_bpf (name);
  if (s->fdsock == -1)
    return -1;
#endif /* not __Linux */

  return 0;
}

int
ethsend (struct ethsock_s *s, void *packet, size_t size)
{
  int n_send;

#ifdef __Linux
  n_send = sendto (s->fdsock, packet, size, 0,
		   (struct sockaddr *) &s->ll, SOCK_LL_SIZE);
  if (n_send == -1)
    {
      DEBUG (4);
      error ("send: %s\n", strerror (errno));
    }
#elif defined (__BSD)
  n_send = write (s->fdsock, packet, size);
  if (n_send == -1)
    {
      DEBUG (3);
      error ("write: %s\n", strerror (errno));
    }
#endif /* not __Linux */
  else if ((size_t) n_send != size)
    error ("WARNING: maybe packet send is troncated\n");
  return n_send;
}

int
ethrecv (int fdsock, void *packet, MONOCLE *monocle)
{
#ifdef __Linux
  int ret;
#endif /* __Linux */
  static char st_packet[PACKET_SIZE];
  struct arp_packet_s *pktrecv = NULL;
#ifdef __BSD
  static size_t offset = 0;
  static size_t totsize = 0;
  struct bpf_hdr *bpf = NULL;
#endif /* __BSD */

#ifdef __Linux
  ret = recv_timeout (fdsock, monocle);
  if (ret < 1)
    return ret;
  ret = xread (fdsock, st_packet, PACKET_SIZE);
  if (ret == -1)
    {
      DEBUG (3);
      error ("read: %s\n", strerror (errno));
      return -1;
    }
  pktrecv = (struct arp_packet_s *) st_packet;
#elif defined (__BSD)
  if (offset >= totsize)
    {
      offset = 0;
      totsize = 0;
      totsize = recv_timeout (fdsock, monocle);
      if (totsize < 1)
	return totsize;
      memset (st_packet, 0, PACKET_SIZE);
      totsize = xread (fdsock, st_packet, PACKET_SIZE);
      if ((int) totsize == -1)
	{
	  DEBUG (3);
	  error ("read: %s\n", strerror (errno));
	  return -1;
	}
    }
  bpf = (struct bpf_hdr *) (st_packet + offset);
  pktrecv = (struct arp_packet_s *) (st_packet
				     + offset
				     + bpf->bh_hdrlen);
#endif /* not __Linux */
  monocle->nrecv++;
  if (pktrecv->eth_protocol == htons (ETH_ARP))
    {
      if (monocle->stat)
	monocle->stat->ps_arp++;
#ifdef __Linux
      memcpy (packet, st_packet, ARP_SIZE);
#elif defined (__BSD)
      memcpy (packet, (st_packet + offset + bpf->bh_hdrlen), ARP_SIZE);
      offset += BPF_WORDALIGN(bpf->bh_hdrlen + bpf->bh_caplen);
#endif /* not __Linux */
      return 1;
    }
#ifdef __BSD
  offset += BPF_WORDALIGN(bpf->bh_hdrlen + bpf->bh_caplen);
#endif /* __BSD */
  return 0;
}

static int
recv_timeout (int fd, MONOCLE *monocle)
{
  int val;
  fd_set read_ok; 
  struct timeval  tv;

  FD_ZERO (&read_ok);
  FD_SET (fd, &read_ok);
  if ((monocle->opt & PASSIV))
    {
      if (!monocle->time)
	return xselect (fd + 1, &read_ok, NULL);
      tv.tv_usec = 0;
      val =  monocle->time -
	(time (NULL) - monocle->start_time);
      tv.tv_sec = (val) ? val : 1;
      return xselect (fd + 1, &read_ok, &tv);
    }
  tv.tv_usec = 3900;
  tv.tv_sec = 0;
  return xselect (fd + 1, &read_ok, &tv);
}

static int
xselect (int fd, fd_set *rd, struct timeval *tv)
{
  int  ret;

  ret = select (fd, rd, NULL, NULL, tv);
  if (ret == -1)
    {
      DEBUG (3);
      if (errno != EINTR)
	error ("select: %s\n", strerror (errno));
    }
  return ret;
}

#ifdef __BSD
static int
get_bpf (const char *name)
{
  int   n;
  int   bpf_fd;
  char  bpf_path[15];

  n = 0;
  do
    {
      snprintf (bpf_path, sizeof (bpf_path) - 1,
		"/dev/bpf%d", n);
      bpf_fd = open (bpf_path, O_RDWR);
    }
  while (bpf_fd == -1 && ++n < 10);
  if (bpf_fd == -1)
    {
      error ("cannot find bpf device\n");
      return -1;
    }
  if (conf_bpf (bpf_fd, name))
    {
      close (bpf_fd);
      return -1;
    }
  return bpf_fd;
}

static int
conf_bpf (int fd, const char *device_name)
{
  int bpf_opt;
  struct ifreq  ifr;

  bpf_opt = PACKET_SIZE;
  if (ioctl (fd, BIOCSBLEN, &bpf_opt) == -1)
    {
      DEBUG (2);
      error ("ioctl (BIOCSBLEN): %s\n", strerror (errno));
      return -1;
    }
  strncpy (ifr.ifr_name, device_name, 10);
  if (ioctl (fd, BIOCSETIF, &ifr) == -1)
    {
      DEBUG (2);
      error ("ioctl (BIOCSETIF): %s\n",  strerror (errno));
      return -1;
    }
  bpf_opt = 1;
  if (ioctl (fd, BIOCIMMEDIATE, &bpf_opt) == -1)
    {
      DEBUG (2);
      error ("ioctl (BIOCIMMEDIATE): %s\n", strerror (errno));
      return -1;
    }
  return 0;
}
#endif /* __BSD */

static int
xread (int fd, void *buf, size_t size)
{
  int ret;

  do
    ret = read (fd, buf, size);
  while (ret == -1 && errno == EINTR);
  return ret;
}
