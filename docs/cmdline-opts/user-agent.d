Short: A
Long: user-agent
Arg: <name>
Help: Send User-Agent <name> to server
Protocols: HTTP
Category: important http
---

Specify the User-Agent string to send to the HTTP server. To encode blanks in
the string, surround the string with single quote marks. This header can also
be set with the --header or the --proxy-header options.

If you give an empty argument to --user-agent (""), it will remove the header
completely from the request. If you prefer a blank header, you can set it to a
single space (" ").

If this option is used several times, the last one will be used.
