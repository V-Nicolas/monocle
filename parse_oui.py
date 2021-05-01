#!/usr/bin/python
#
#       parse_oui, (C) 2011) Vilmain Nicolas (nicolas.vilmain@gmail.com)
#
#       $ python parse_oui.py
#       http://standards.ieee.org/develop/regauth/oui/oui.txt
#       input: oui-raw.txt
#       output oui.txt, format: 000000:name
#
#       This program is free software: you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation, either version 3 of the License, or
#       (at your option) any later version.
#
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#
#       You should have received a copy of the GNU General Public License
#       along with this program.  If not, see <http://www.gnu.org/licenses/>.

import string

def main ():
    try:
        file_input = open ("oui-raw.txt", 'r')
        file_output = open ("oui.txt", 'w')
    except:
        print "open file error"
        exit (-1)
    line = file_input.readline ()
    while (line != ""):
        if (line.find ("(base 16)") != -1):
            idx = line.find ("\t\t")
            if (idx != -1):
                file_output.write ("%s:%s"%(line[:6], line[idx + 2:]))
        line = file_input.readline ()
    file_input.close ()
    file_output.close ()

if (__name__ == "__main__"):
    main ()
