Long: range
Short: r
Help: Retrieve only the bytes within RANGE
Arg: <range>
Protocols: HTTP FTP SFTP FILE
Category: http ftp sftp file
---
Retrieve a byte range (i.e. a partial document) from an HTTP/1.1, FTP or SFTP
server or a local FILE. Ranges can be specified in a number of ways.
.RS
.TP 10
.B 0-499
specifies the first 500 bytes
.TP
.B 500-999
specifies the second 500 bytes
.TP
.B -500
specifies the last 500 bytes
.TP
.B 9500-
specifies the bytes from offset 9500 and forward
.TP
.B 0-0,-1
specifies the first and last byte only(*)(HTTP)
.TP
.B 100-199,500-599
specifies two separate 100-byte ranges(*) (HTTP)
.RE
.IP
(*) = NOTE that this will cause the server to reply with a multipart
response, which will be returned as-is by curl! Parsing or otherwise
transforming this response is the responsibility of the caller.

Only digit characters (0-9) are valid in the 'start' and 'stop' fields of the
\&'start-stop' range syntax. If a non-digit character is given in the range,
the server's response will be unspecified, depending on the server's
configuration.

You should also be aware that many HTTP/1.1 servers do not have this feature
enabled, so that when you attempt to get a range, you'll instead get the whole
document.

FTP and SFTP range downloads only support the simple 'start-stop' syntax
(optionally with one of the numbers omitted). FTP use depends on the extended
FTP command SIZE.

If this option is used several times, the last one will be used.
