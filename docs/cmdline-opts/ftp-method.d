Long: ftp-method
Arg: <method>
Help: Control CWD usage
Protocols: FTP
Added: 7.15.1
Category: ftp
Example: --ftp-method multicwd ftp://example.com/dir1/dir2/file
Example: --ftp-method nocwd ftp://example.com/dir1/dir2/file
Example: --ftp-method singlecwd ftp://example.com/dir1/dir2/file
---
Control what method curl should use to reach a file on an FTP(S)
server. The method argument should be one of the following alternatives:
.RS
.IP multicwd
curl does a single CWD operation for each path part in the given URL. For deep
hierarchies this means very many commands. This is how RFC 1738 says it should
be done. This is the default but the slowest behavior.
.IP nocwd
curl does no CWD at all. curl will do SIZE, RETR, STOR etc and give a full
path to the server for all these commands. This is the fastest behavior.
.IP singlecwd
curl does one CWD with the full target directory and then operates on the file
\&"normally" (like in the multicwd case). This is somewhat more standards
compliant than 'nocwd' but without the full penalty of 'multicwd'.
.RE
