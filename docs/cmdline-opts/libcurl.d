Long: libcurl
Arg: <file>
Help: Dump libcurl equivalent code of this command line
Added: 7.16.1
---
Append this option to any ordinary curl command line, and you will get a
libcurl-using C source code written to the file that does the equivalent
of what your command-line operation does!

If this option is used several times, the last given file name will be
used.
