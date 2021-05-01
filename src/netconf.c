/*
 *  monocle
 *  src/netconf.c
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

static int   get_interface (struct netconf_s *nc, struct ifaddrs *ifa,
			    const char *name);
static int   get_interface_address (struct ifaddrs *ifa, struct netconf_s *nc);
static int   get_interface_more_data (struct netconf_s *nc);

int
get_netconf (struct netconf_s *nc, const char *name)
{
  int ret;
  struct ifaddrs *ifa = NULL;

  memset (nc, 0, sizeof (struct netconf_s));
  if (getifaddrs (&ifa) == -1)
    {
      DEBUG (2);
      error ("getifaddrs: %s\n", strerror (errno));
      return -1;
    }
  ret = get_interface (nc, ifa, name);
  freeifaddrs (ifa);
  return ret;
}

static int
get_interface (struct netconf_s *nc, struct ifaddrs *ifa,
	       const char *name)
{
  struct ifaddrs  *p_ifa = NULL;

  p_ifa = ifa;
  while (p_ifa)
    {
      if (!(p_ifa->ifa_flags & IFF_LOOPBACK)
	  && (p_ifa->ifa_flags & IFF_RUNNING)
	  && (p_ifa->ifa_addr != 0)
	  && (p_ifa->ifa_addr->sa_family == AF_INET)
	  && ((!name || !name[0])
	      || !strcmp (name, p_ifa->ifa_name)))
	{
	  strncpy (nc->nc_name, p_ifa->ifa_name, (NAME_LEN - 1));
	  return (get_interface_address (ifa, nc) == -1
		  || get_interface_more_data (nc) == -1) ? -1 : 0;
	}
      p_ifa = p_ifa->ifa_next;
    }
  error ("cannot find or valid network interface\n");
  return -1;
}

static int
get_interface_address (struct ifaddrs *ifa, struct netconf_s *nc)
{
#ifdef __BSD
  struct sockaddr_dl  *dl = NULL;
  int  mac_addrs_found;

  mac_addrs_found = 0;
#endif /* __BSD */
  while (ifa)
    {
      if (!strcmp (ifa->ifa_name, nc->nc_name))
	{
	  if (ifa->ifa_addr->sa_family == AF_INET)
	    {
	      memcpy (&nc->nc_ipv4,
		      &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr,
		      sizeof (struct in_addr));
	    }
#ifdef __BSD
	  else if (ifa->ifa_addr->sa_family == AF_LINK)
	    {
	      mac_addrs_found++;
	      dl = (struct sockaddr_dl *) ifa->ifa_addr;
	      COPY_MAC (nc->nc_mac, LLADDR (dl));
	    }
#endif /* __BSD */
	}
      ifa = ifa->ifa_next;
    }
#ifdef __BSD
  if (!mac_addrs_found)
    {
      error ("address mac not found\n");
      return -1;
    }
#endif /* __BSD */
  return 0;
}

static int
get_interface_more_data (struct netconf_s *nc)
{
  int           fd;
  struct ifreq  ifr;

  fd = socket (AF_INET, SOCK_DGRAM, 0);
  if (fd == -1)
    {
      DEBUG (3);
      error ("socket: %s\n", strerror (errno));
      return -1;
    }
  memset (&ifr, 0, sizeof (struct ifreq));
  strncpy (ifr.ifr_name, nc->nc_name, (NAME_LEN - 1));
  if (ioctl (fd, SIOCGIFMTU, &ifr) == -1)
    {
      DEBUG (2);
      error ("ioctl (SIOCGIFMTU): %s\n", strerror (errno));
      close (fd);
      return -1;
    }
  nc->nc_mtu = ifr.ifr_ifru.ifru_mtu;
  if (ioctl (fd, SIOCGIFINDEX, &ifr) == -1)
    {
      DEBUG (2);
      error ("ioctl (SIOCGIFINDEX): %s\n",  strerror (errno));
      close (fd);
      return -1;
    }
#ifdef __BSD
  nc->nc_index = ifr.ifr_index;
#elif defined(__Linux)
  nc->nc_index = ifr.ifr_ifindex;
  if (ioctl (fd, SIOCGIFHWADDR, &ifr) == -1)
    {
      DEBUG (2);
      error ("ioctl (SIOCGIFHWADDR): %s\n", strerror (errno));
      close (fd);
      return -1;
    }
  COPY_MAC (nc->nc_mac, ifr.ifr_hwaddr.sa_data);
#endif /* __Linux */
  close (fd);
  return 0;
}
