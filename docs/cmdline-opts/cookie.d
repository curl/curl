Short: b
Long: cookie
Arg: <data|filename>
Protocols: HTTP
Help: Send cookies from string/file
Category: http
---
Pass the data to the HTTP server in the Cookie header. It is supposedly
the data previously received from the server in a "Set-Cookie:" line.  The
data should be in the format "NAME1=VALUE1; NAME2=VALUE2".

If no '=' symbol is used in the argument, it is instead treated as a filename
to read previously stored cookie from. This option also activates the cookie
engine which will make curl record incoming cookies, which may be handy if
you're using this in combination with the --location option or do multiple URL
transfers on the same invoke. If the file name is exactly a minus ("-"), curl
will instead read the contents from stdin.

The file format of the file to read cookies from should be plain HTTP headers
(Set-Cookie style) or the Netscape/Mozilla cookie file format.

The file specified with --cookie is only used as input. No cookies will be
written to the file. To store cookies, use the --cookie-jar option.

Exercise caution if you are using this option and multiple transfers may
occur.  If you use the NAME1=VALUE1; format, or in a file use the Set-Cookie
format and don't specify a domain, then the cookie is sent for any domain
(even after redirects are followed) and cannot be modified by a server-set
cookie. If the cookie engine is enabled and a server sets a cookie of the same
name then both will be sent on a future transfer to that server, likely not
what you intended.  To address these issues set a domain in Set-Cookie (doing
that will include sub domains) or use the Netscape format.

If this option is used several times, the last one will be used.

Users very often want to both read cookies from a file and write updated
cookies back to a file, so using both --cookie and --cookie-jar in the same
command line is common.
