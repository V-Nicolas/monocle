/*
 *  monocle
 *  src/oui.c
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

#include  <ctype.h>
#include  "monocle.h"

void
open_file_oui (MONOCLE *monocle)
{
  if (!monocle->file_oui)
    {
      /* try ./oui.txt file */
      monocle->file_oui = fopen ("./oui.txt", "r");
      if (!monocle->file_oui)
	{
	  /* try /etc/monocle/oui.txt */
	  monocle->file_oui = fopen ("/etc/monocle/oui.txt", "r");
	  if (!monocle->file_oui)
	    {
	      fprintf (stderr, "%s:warning: open oui.txt fail: %s\n",
		       program_name, strerror (errno));
	    }
	}
    }
}

#define LINESIZE  248
#define _LINESIZE 247

void
file_oui_search_mac_vendor (FILE *oui, uint8_t *mac)
{
  char line[LINESIZE];
  char *rmretline = NULL;
  char upper_mac[7];
  unsigned int i;

  if (oui)
    {
      rewind (oui);
      snprintf (upper_mac, 7, "%02x%02x%02x", mac[0] & 0xff,
		mac[1] & 0xff, mac[2] & 0xff);
      for (i = 0; i < 7; i++)
	{
	  if (islower (upper_mac[i]))
	    upper_mac[i] = toupper (upper_mac[i]);
	}
      while (!feof (oui) && !ferror (oui))
	{
	  if (fgets (line, _LINESIZE, oui))
	    {
	      if (!memcmp (upper_mac, line, 6))
		{
		  rmretline = line + (strlen (line) - 1);
		  if (*rmretline == '\n')
		    *rmretline = 0;
		  printf ("%s", (*(line + 7)) ? (line + 7) : "");
		  break;
		}
	    }
	}
    }
}
