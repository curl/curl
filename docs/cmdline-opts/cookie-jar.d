Short: c
Long: cookie-jar
Arg: <filename>
Protocols: HTTP
Help: Write cookies to <filename> after operation
Category: http
Example: -c store-here.txt $URL
Example: -c store-here.txt -b read-these $URL
Added: 7.9
---
Specify to which file you want curl to write all cookies after a completed
operation. Curl writes all cookies from its in-memory cookie storage to the
given file at the end of operations. If no cookies are known, no data will be
written. The file will be written using the Netscape cookie file format. If
you set the file name to a single dash, "-", the cookies will be written to
stdout.

This command line option will activate the cookie engine that makes curl
record and use cookies. Another way to activate it is to use the --cookie
option.

If the cookie jar cannot be created or written to, the whole curl operation
will not fail or even report an error clearly. Using --verbose will get a
warning displayed, but that is the only visible feedback you get about this
possibly lethal situation.

If this option is used several times, the last specified file name will be
used.
