c: Copyright (C) 1998 - 2022, Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: curl
Long: output
Arg: <file>
Short: o
Help: Write to file instead of stdout
See-also: remote-name remote-name-all remote-header-name
Category: important curl
Example: -o file $URL
Example: "http://{one,two}.example.com" -o "file_#1.txt"
Example: "http://{site,host}.host[1-5].com" -o "#1_#2"
Example: -o file $URL -o file2 https://example.net
Added: 4.0
Multi: append
---
Write output to <file> instead of stdout. If you are using {} or [] to fetch
multiple documents, you should quote the URL and you can use '#' followed by a
number in the <file> specifier. That variable will be replaced with the current
string for the URL being fetched. Like in:

 curl "http://{one,two}.example.com" -o "file_#1.txt"

or use several variables like:

 curl "http://{site,host}.host[1-5].com" -o "#1_#2"

You may use this option as many times as the number of URLs you have. For
example, if you specify two URLs on the same command line, you can use it like
this:

  curl -o aa example.com -o bb example.net

and the order of the -o options and the URLs does not matter, just that the
first -o is for the first URL and so on, so the above command line can also be
written as

  curl example.com example.net -o aa -o bb

See also the --create-dirs option to create the local directories
dynamically. Specifying the output as '-' (a single dash) will force the
output to be done to stdout.

To suppress response bodies, you can redirect output to /dev/null:

  curl example.com -o /dev/null

Or for Windows use nul:

  curl example.com -o nul
