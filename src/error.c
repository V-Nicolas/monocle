/*
 *  monocle
 *  src/error.c
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

void
error (const char *fmt, ...)
{
  va_list  va;

  va_start (va, fmt);
  if (!debug)
    fprintf (stderr, "%s:", program_name);
  vfprintf (stderr, fmt, va);
  va_end (va);
}
