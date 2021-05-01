/*
 *  monocle
 *  src/error.h
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

#ifndef __ERROR_H__
#define __ERROR_H__

extern char *program_name;
extern int debug;

#ifdef __GNUC__
# define  __FUNCTION_NAME__  __FUNCTION__
#else
# define  __FUNCTION_NAME__  __func__
#endif /* __GNUC__ */

#define DEBUG(i)                    \
  if (debug)                        \
    {                            \
      fprintf (stderr, "%s:%s:%s:%d:", program_name,    \
           __FILE__, __FUNCTION_NAME__,        \
           (__LINE__ - i));                \
    }

void error(const char *fmt, ...);

#endif /* not __ERROR_H__ */
