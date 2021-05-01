/*
 *  monocle
 *  src/mem.c
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

static void  out_memory (const char *err);

static void
out_memory (const char *err)
{
  fprintf (stderr, "%s:%s: memory exhausted\n",
	   program_name, err);
  exit (EXIT_FAILURE);
}

void *
xcalloc (size_t size)
{
  void *ptr = NULL;

  ptr = malloc (size);
  if (!ptr)
    out_memory ("malloc");
  memset (ptr, 0, size);
  return ptr;
}

void *
xmalloc (size_t size)
{
  void *ptr = NULL;

  ptr = malloc (size);
  if (!ptr)
    out_memory ("malloc");
  return ptr;
}
